package ninjapanda

import (
	"reflect"
	"strings"

	"github.com/pkg/errors"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

func StructToStruct(
	filter FieldFilter,
	src, dst interface{},
	userOpts ...Option,
) error {
	opts := newDefaultOptions()
	for _, o := range userOpts {
		o(opts)
	}

	dstVal := reflect.ValueOf(dst)
	if dstVal.Kind() != reflect.Ptr {
		return errors.Errorf("dst must be a pointer, %s given", dstVal.Kind())
	}
	srcVal := indirect(reflect.ValueOf(src))
	if srcVal.Kind() != reflect.Struct {
		return errors.Errorf("src kind must be a struct, %s given", srcVal.Kind())
	}
	dstVal = indirect(dstVal)
	if dstVal.Kind() != reflect.Struct {
		return errors.Errorf("dst kind must be a struct, %s given", dstVal.Kind())
	}
	return structToStruct(filter, &srcVal, &dstVal, opts)
}

func ensureCompatible(src, dst *reflect.Value) error {
	srcKind := src.Kind()
	if srcKind == reflect.Ptr {
		srcKind = src.Type().Elem().Kind()
	}
	dstKind := dst.Kind()
	if dstKind == reflect.Ptr {
		dstKind = dst.Type().Elem().Kind()
	}
	if srcKind != dstKind {
		return errors.Errorf("src kind %s differs from dst kind %s", srcKind, dstKind)
	}
	return nil
}

func structToStruct(
	filter FieldFilter,
	src, dst *reflect.Value,
	userOptions *options,
) error {
	if err := ensureCompatible(src, dst); err != nil {
		return err
	}

	switch src.Kind() {
	case reflect.Struct:
		if dst.CanSet() && dst.Type().AssignableTo(src.Type()) && filter.IsEmpty() {
			dst.Set(*src)
			return nil
		}

		if dst.Kind() == reflect.Ptr {
			if dst.IsNil() {
				dst.Set(reflect.New(dst.Type().Elem()))
			}
			v := dst.Elem()
			dst = &v
		}

		for i := 0; i < src.NumField(); i++ {
			srcType := src.Type()
			srcName := fieldName(userOptions.SrcTag, srcType.Field(i))
			dstName := fieldName(userOptions.DstTag, srcType.Field(i))

			subFilter, ok := filter.Filter(srcName)
			if !ok {
				continue
			}

			srcField := src.Field(i)
			if !srcField.CanInterface() {
				continue
			}

			dstField := dst.FieldByName(dstName)
			if !dstField.CanSet() {
				return errors.Errorf(
					"Can not set a value on a destination field %s",
					dstName,
				)
			}

			if err := structToStruct(subFilter, &srcField, &dstField, userOptions); err != nil {
				return err
			}
		}

	case reflect.Ptr:
		if src.IsNil() {
			dst.Set(reflect.Zero(dst.Type()))
			break
		}
		if dst.Kind() == reflect.Ptr && dst.IsNil() {
			dst.Set(reflect.New(dst.Type().Elem()))
		}

		if srcAny, ok := src.Interface().(*anypb.Any); ok {
			dstAny, ok := dst.Interface().(*anypb.Any)
			if !ok {
				return errors.Errorf(
					"dst type is %s, expected: %s ",
					dst.Type(),
					"*any.Any",
				)
			}

			srcProto, err := srcAny.UnmarshalNew()
			if err != nil {
				return errors.WithStack(err)
			}
			srcProtoValue := reflect.ValueOf(srcProto)

			if dstAny.GetTypeUrl() == "" {
				dstAny.TypeUrl = srcAny.GetTypeUrl()
			}
			dstProto, err := dstAny.UnmarshalNew()
			if err != nil {
				return errors.WithStack(err)
			}
			dstProtoValue := reflect.ValueOf(dstProto)

			if err := structToStruct(filter, &srcProtoValue, &dstProtoValue, userOptions); err != nil {
				return err
			}

			newDstAny := new(anypb.Any)
			if err := newDstAny.MarshalFrom(dstProtoValue.Interface().(proto.Message)); err != nil {
				return errors.WithStack(err)
			}

			dst.Set(reflect.ValueOf(newDstAny))
			break
		}

		srcElem, dstElem := src.Elem(), *dst
		if dst.Kind() == reflect.Ptr {
			dstElem = dst.Elem()
		}

		if err := structToStruct(filter, &srcElem, &dstElem, userOptions); err != nil {
			return err
		}

	case reflect.Interface:
		if src.IsNil() {
			dst.Set(reflect.Zero(dst.Type()))
			break
		}
		if dst.IsNil() {
			if src.Elem().Kind() != reflect.Ptr {
				return errors.Errorf(
					"expected a pointer for an interface value, got %s instead",
					src.Elem().Kind(),
				)
			}
			dst.Set(reflect.New(src.Elem().Elem().Type()))
		}

		srcElem, dstElem := src.Elem(), dst.Elem()
		if err := structToStruct(filter, &srcElem, &dstElem, userOptions); err != nil {
			return err
		}

	case reflect.Slice:
		if src.IsNil() {
			dst.Set(*src)
			break
		}

		dstLen := dst.Len()
		srcLen := userOptions.CopyListSize(src)

		for i := 0; i < srcLen; i++ {
			srcItem := src.Index(i)
			var dstItem reflect.Value
			if i < dstLen {
				dstItem = dst.Index(i)
			} else {
				dstItem = reflect.New(dst.Type().Elem()).Elem()
			}

			if err := structToStruct(filter, &srcItem, &dstItem, userOptions); err != nil {
				return err
			}

			if i >= dstLen {
				dst.Set(reflect.Append(*dst, dstItem))
			}
		}
		if dstLen > srcLen {
			dst.SetLen(srcLen)
		}

	case reflect.Array:
		dstLen := dst.Len()
		srcLen := userOptions.CopyListSize(src)
		if dstLen < srcLen {
			return errors.Errorf(
				"dst array size %d is less than src size %d",
				dstLen,
				srcLen,
			)
		}
		for i := 0; i < srcLen; i++ {
			srcItem := src.Index(i)
			dstItem := dst.Index(i)
			if err := structToStruct(filter, &srcItem, &dstItem, userOptions); err != nil {
				return errors.WithStack(err)
			}
		}

	default:
		if !dst.CanSet() {
			return errors.Errorf("dst %s, %s is not settable", dst, dst.Type())
		}
		if dst.Kind() == reflect.Ptr {
			if !src.CanAddr() {
				return errors.Errorf("src %s, %s is not addressable", src, src.Type())
			}
			dst.Set(src.Addr())
		} else {
			dst.Set(*src)
		}
	}

	return nil
}

type options struct {
	DstTag string

	SrcTag string

	CopyListSize func(src *reflect.Value) int

	MapVisitor mapVisitor
}

type mapVisitor func(
	filter FieldFilter, src, dst reflect.Value,
	srcFieldName, dstFieldName string, srcFieldValue reflect.Value) MapVisitorResult

type MapVisitorResult struct {
	SkipToNext bool
	UpdatedDst *reflect.Value
}

type Option func(*options)

func WithTag(s string) Option {
	return func(o *options) {
		o.DstTag = s
	}
}

func WithSrcTag(s string) Option {
	return func(o *options) {
		o.SrcTag = s
	}
}

func WithCopyListSize(f func(src *reflect.Value) int) Option {
	return func(o *options) {
		o.CopyListSize = f
	}
}

func WithMapVisitor(visitor mapVisitor) Option {
	return func(o *options) {
		o.MapVisitor = visitor
	}
}

func newDefaultOptions() *options {
	return &options{CopyListSize: func(src *reflect.Value) int { return src.Len() }}
}

func fieldName(tag string, f reflect.StructField) string {
	if tag == "" {
		return f.Name
	}
	lookupResult, ok := f.Tag.Lookup(tag)
	if !ok {
		return f.Name
	}
	firstComma := strings.Index(lookupResult, ",")
	if firstComma == -1 {
		return lookupResult
	}
	return lookupResult[:firstComma]
}

func StructToMap(
	filter FieldFilter,
	src interface{},
	dst map[string]interface{},
	userOpts ...Option,
) error {
	opts := newDefaultOptions()
	for _, o := range userOpts {
		o(opts)
	}
	_, err := structToMap(filter, reflect.ValueOf(src), reflect.ValueOf(dst), opts)
	return err
}

func structToMap(
	filter FieldFilter,
	src, dst reflect.Value,
	userOptions *options,
) (reflect.Value, error) {
	switch src.Kind() {
	case reflect.Struct:
		if dst.Kind() != reflect.Map {
			return dst, errors.Errorf(
				"incompatible destination kind: %s, expected map",
				dst.Kind(),
			)
		}
		srcType := src.Type()
		for i := 0; i < src.NumField(); i++ {
			srcName := fieldName(userOptions.SrcTag, srcType.Field(i))
			if !isExported(srcType.Field(i)) {
				continue
			}

			subFilter, ok := filter.Filter(srcName)
			if !ok {
				continue
			}
			srcField := indirect(src.Field(i))
			dstName := fieldName(userOptions.DstTag, srcType.Field(i))
			mapValue := indirect(dst.MapIndex(reflect.ValueOf(dstName)))
			if !mapValue.IsValid() {
				if srcField.IsValid() {
					mapValue = newValue(srcField.Type())
				} else {
					dstMap := dst.Interface().(map[string]interface{})
					dstMap[dstName] = nil
					continue
				}
			}
			if userOptions.MapVisitor != nil {
				result := userOptions.MapVisitor(
					filter,
					src,
					mapValue,
					srcName,
					dstName,
					srcField,
				)
				if result.UpdatedDst != nil {
					mapValue = *result.UpdatedDst
				}
				if result.SkipToNext {
					if result.UpdatedDst != nil {
						dst.SetMapIndex(reflect.ValueOf(dstName), mapValue)
					}
					continue
				}
			}
			if isPrimitive(mapValue.Kind()) {
				dst.SetMapIndex(reflect.ValueOf(dstName), srcField)
				continue
			}
			var err error
			if mapValue, err = structToMap(subFilter, srcField, mapValue, userOptions); err != nil {
				return dst, err
			}
			dst.SetMapIndex(reflect.ValueOf(dstName), mapValue)
		}

	case reflect.Ptr:
		if src.IsNil() {
			reflect.ValueOf(dst).Set(reflect.ValueOf(nil))
			break
		}
		var err error
		if dst, err = structToMap(filter, indirect(src), dst, userOptions); err != nil {
			return dst, err
		}

	case reflect.Interface:
		if src.IsNil() {
			reflect.ValueOf(dst).Set(reflect.ValueOf(nil))
			break
		}

		var err error
		if dst, err = structToMap(filter, indirect(src), dst, userOptions); err != nil {
			return dst, err
		}

	case reflect.Array, reflect.Slice:
		if dstKind := dst.Kind(); dstKind != reflect.Slice && dstKind != reflect.Array {
			return dst, errors.Errorf(
				"incompatible destination kind: %s, expected slice",
				dst.Kind(),
			)
		}
		itemType := src.Type().Elem()
		desiredDstLen := userOptions.CopyListSize(&src)
		itemKind := itemType.Kind()
		if isPrimitive(itemKind) {
			if desiredDstLen < src.Len() {
				dst = src.Slice(0, desiredDstLen)
			} else {
				dst = src
			}
		} else {
			if dst.Kind() == reflect.Array {
				sliceDst := newValue(src.Type())
				for i := 0; i < dst.Len(); i++ {
					sliceDst = reflect.Append(sliceDst, dst.Index(i))
				}
				dst = sliceDst
			}
			var err error
			for i := 0; i < desiredDstLen; i++ {
				itemExists := false
				var subDst reflect.Value
				if i < dst.Len() {
					subDst = dst.Index(i)
					itemExists = true
				} else {
					subDst = newValue(itemType)
				}
				if subDst, err = structToMap(filter, src.Index(i), subDst, userOptions); err != nil {
					return subDst, err
				}
				if !itemExists {
					dst = reflect.Append(dst, subDst)
				}
			}
			if desiredDstLen < dst.Len() {
				dst = dst.Slice(0, desiredDstLen)
			}
		}

	case reflect.Invalid:
		dst.Set(reflect.ValueOf(nil))

	default:
		dst.Set(src)
	}
	return dst, nil
}

func indirect(v reflect.Value) reflect.Value {
	for v.Kind() == reflect.Ptr || v.Kind() == reflect.Interface {
		v = v.Elem()
	}
	return v
}

func isPrimitive(kind reflect.Kind) bool {
	return kind != reflect.Ptr &&
		kind != reflect.Struct &&
		kind != reflect.Interface &&
		kind != reflect.Slice &&
		kind != reflect.Array &&
		kind != reflect.Map
}

func newValue(t reflect.Type) reflect.Value {
	switch t.Kind() {
	case reflect.Struct:
		return reflect.MakeMap(reflect.TypeOf(map[string]interface{}{}))

	case reflect.Array, reflect.Slice:
		return reflect.MakeSlice(reflect.SliceOf(newValue(t.Elem()).Type()), 0, 0)

	case reflect.Ptr:
		return newValue(t.Elem())

	default:
		return reflect.New(t).Elem()
	}
}

func isExported(f reflect.StructField) bool {
	return f.PkgPath == ""
}
