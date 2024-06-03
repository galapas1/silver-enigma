package structs

import (
	"fmt"
	"reflect"
)

var DefaultTagName = "structs"

type Struct struct {
	raw     interface{}
	value   reflect.Value
	TagName string
}

func New(s interface{}) *Struct {
	return &Struct{
		raw:     s,
		value:   strctVal(s),
		TagName: DefaultTagName,
	}
}

func (s *Struct) Map() map[string]interface{} {
	out := make(map[string]interface{})
	s.FillMap(out)
	return out
}

func (s *Struct) FillMap(out map[string]interface{}) {
	if out == nil {
		return
	}

	fields := s.structFields()

	for _, field := range fields {
		name := field.Name
		val := s.value.FieldByName(name)
		isSubStruct := false
		var finalVal interface{}

		tagName, tagOpts := parseTag(field.Tag.Get(s.TagName))
		if tagName != "" {
			name = tagName
		}

		if tagOpts.Has("omitempty") {
			zero := reflect.Zero(val.Type()).Interface()
			current := val.Interface()

			if reflect.DeepEqual(current, zero) {
				continue
			}
		}

		if !tagOpts.Has("omitnested") {
			finalVal = s.nested(val)

			v := reflect.ValueOf(val.Interface())
			if v.Kind() == reflect.Ptr {
				v = v.Elem()
			}

			switch v.Kind() {
			case reflect.Map, reflect.Struct:
				isSubStruct = true
			}
		} else {
			finalVal = val.Interface()
		}

		if tagOpts.Has("string") {
			s, ok := val.Interface().(fmt.Stringer)
			if ok {
				out[name] = s.String()
			}
			continue
		}

		if isSubStruct && (tagOpts.Has("flatten")) {
			for k := range finalVal.(map[string]interface{}) {
				out[k] = finalVal.(map[string]interface{})[k]
			}
		} else {
			out[name] = finalVal
		}
	}
}

func (s *Struct) Values() []interface{} {
	fields := s.structFields()

	var t []interface{}

	for _, field := range fields {
		val := s.value.FieldByName(field.Name)

		_, tagOpts := parseTag(field.Tag.Get(s.TagName))

		if tagOpts.Has("omitempty") {
			zero := reflect.Zero(val.Type()).Interface()
			current := val.Interface()

			if reflect.DeepEqual(current, zero) {
				continue
			}
		}

		if tagOpts.Has("string") {
			s, ok := val.Interface().(fmt.Stringer)
			if ok {
				t = append(t, s.String())
			}
			continue
		}

		if IsStruct(val.Interface()) && !tagOpts.Has("omitnested") {
			t = append(t, Values(val.Interface())...)
		} else {
			t = append(t, val.Interface())
		}
	}

	return t
}

func (s *Struct) Fields() []*Field {
	return getFields(s.value, s.TagName)
}

func (s *Struct) Names() []string {
	fields := getFields(s.value, s.TagName)

	names := make([]string, len(fields))

	for i, field := range fields {
		names[i] = field.Name()
	}

	return names
}

func getFields(v reflect.Value, tagName string) []*Field {
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}

	t := v.Type()

	var fields []*Field

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)

		if tag := field.Tag.Get(tagName); tag == "-" {
			continue
		}

		f := &Field{
			field: field,
			value: v.FieldByName(field.Name),
		}

		fields = append(fields, f)

	}

	return fields
}

func (s *Struct) Field(name string) *Field {
	f, ok := s.FieldOk(name)
	if !ok {
		panic("field not found")
	}

	return f
}

func (s *Struct) FieldOk(name string) (*Field, bool) {
	t := s.value.Type()

	field, ok := t.FieldByName(name)
	if !ok {
		return nil, false
	}

	return &Field{
		field:      field,
		value:      s.value.FieldByName(name),
		defaultTag: s.TagName,
	}, true
}

func (s *Struct) IsZero() bool {
	fields := s.structFields()

	for _, field := range fields {
		val := s.value.FieldByName(field.Name)

		_, tagOpts := parseTag(field.Tag.Get(s.TagName))

		if IsStruct(val.Interface()) && !tagOpts.Has("omitnested") {
			ok := IsZero(val.Interface())
			if !ok {
				return false
			}

			continue
		}

		zero := reflect.Zero(val.Type()).Interface()
		current := val.Interface()

		if !reflect.DeepEqual(current, zero) {
			return false
		}
	}

	return true
}

func (s *Struct) HasZero() bool {
	fields := s.structFields()

	for _, field := range fields {
		val := s.value.FieldByName(field.Name)

		_, tagOpts := parseTag(field.Tag.Get(s.TagName))

		if IsStruct(val.Interface()) && !tagOpts.Has("omitnested") {
			ok := HasZero(val.Interface())
			if ok {
				return true
			}

			continue
		}

		zero := reflect.Zero(val.Type()).Interface()
		current := val.Interface()

		if reflect.DeepEqual(current, zero) {
			return true
		}
	}

	return false
}

func (s *Struct) Name() string {
	return s.value.Type().Name()
}

func (s *Struct) structFields() []reflect.StructField {
	t := s.value.Type()

	var f []reflect.StructField

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		if field.PkgPath != "" {
			continue
		}

		if tag := field.Tag.Get(s.TagName); tag == "-" {
			continue
		}

		f = append(f, field)
	}

	return f
}

func strctVal(s interface{}) reflect.Value {
	v := reflect.ValueOf(s)

	for v.Kind() == reflect.Ptr {
		v = v.Elem()
	}

	if v.Kind() != reflect.Struct {
		panic("not struct")
	}

	return v
}

func Map(s interface{}) map[string]interface{} {
	return New(s).Map()
}

func FillMap(s interface{}, out map[string]interface{}) {
	New(s).FillMap(out)
}

func Values(s interface{}) []interface{} {
	return New(s).Values()
}

func Fields(s interface{}) []*Field {
	return New(s).Fields()
}

func Names(s interface{}) []string {
	return New(s).Names()
}

func IsZero(s interface{}) bool {
	return New(s).IsZero()
}

func HasZero(s interface{}) bool {
	return New(s).HasZero()
}

func IsStruct(s interface{}) bool {
	v := reflect.ValueOf(s)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}

	if v.Kind() == reflect.Invalid {
		return false
	}

	return v.Kind() == reflect.Struct
}

func Name(s interface{}) string {
	return New(s).Name()
}

func (s *Struct) nested(val reflect.Value) interface{} {
	var finalVal interface{}

	v := reflect.ValueOf(val.Interface())
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}

	switch v.Kind() {
	case reflect.Struct:
		n := New(val.Interface())
		n.TagName = s.TagName
		m := n.Map()

		if len(m) == 0 {
			finalVal = val.Interface()
		} else {
			finalVal = m
		}
	case reflect.Map:
		mapElem := val.Type()
		switch val.Type().Kind() {
		case reflect.Ptr, reflect.Array, reflect.Map,
			reflect.Slice, reflect.Chan:
			mapElem = val.Type().Elem()
			if mapElem.Kind() == reflect.Ptr {
				mapElem = mapElem.Elem()
			}
		}

		if mapElem.Kind() == reflect.Struct ||
			(mapElem.Kind() == reflect.Slice &&
				mapElem.Elem().Kind() == reflect.Struct) {
			m := make(map[string]interface{}, val.Len())
			for _, k := range val.MapKeys() {
				m[k.String()] = s.nested(val.MapIndex(k))
			}
			finalVal = m
			break
		}

		finalVal = val.Interface()
	case reflect.Slice, reflect.Array:
		if val.Type().Kind() == reflect.Interface {
			finalVal = val.Interface()
			break
		}

		if val.Type().Elem().Kind() != reflect.Struct &&
			!(val.Type().Elem().Kind() == reflect.Ptr &&
				val.Type().Elem().Elem().Kind() == reflect.Struct) {
			finalVal = val.Interface()
			break
		}

		slices := make([]interface{}, val.Len())
		for x := 0; x < val.Len(); x++ {
			slices[x] = s.nested(val.Index(x))
		}
		finalVal = slices
	default:
		finalVal = val.Interface()
	}

	return finalVal
}
