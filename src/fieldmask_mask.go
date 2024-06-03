package ninjapanda

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"google.golang.org/genproto/protobuf/field_mask"
)

type FieldFilter interface {
	Filter(fieldName string) (FieldFilter, bool)
	IsEmpty() bool
}

type FieldFilterContainer interface {
	FieldFilter
	Get(fieldName string) (filter FieldFilterContainer, result bool)
	Set(fieldName string, filter FieldFilterContainer)
}

type Mask map[string]FieldFilterContainer

func (m Mask) Get(fieldName string) (FieldFilterContainer, bool) {
	f, ok := m[fieldName]
	return f, ok
}

func (m Mask) Set(fieldName string, filter FieldFilterContainer) {
	m[fieldName] = filter
}

var _ FieldFilter = Mask{}

func (m Mask) Filter(fieldName string) (FieldFilter, bool) {
	if len(m) == 0 {
		return Mask{}, !strings.HasPrefix(fieldName, "XXX_")
	}
	subFilter, ok := m[fieldName]
	if !ok {
		subFilter = Mask{}
	}
	return subFilter, ok
}

func (m Mask) IsEmpty() bool {
	return len(m) == 0
}

func mapToString(m map[string]FieldFilterContainer) string {
	if len(m) == 0 {
		return ""
	}
	var result []string
	for fieldName, maskNode := range m {
		r := fieldName
		var sub string
		if stringer, ok := maskNode.(fmt.Stringer); ok {
			sub = stringer.String()
		} else {
			sub = fmt.Sprint(maskNode)
		}
		if sub != "" {
			r += "{" + sub + "}"
		}
		result = append(result, r)
	}
	return strings.Join(result, ",")
}

func (m Mask) String() string {
	return mapToString(m)
}

type MaskInverse map[string]FieldFilterContainer

func (m MaskInverse) Get(fieldName string) (FieldFilterContainer, bool) {
	f, ok := m[fieldName]
	return f, ok
}

func (m MaskInverse) Set(fieldName string, filter FieldFilterContainer) {
	m[fieldName] = filter
}

func (m MaskInverse) Filter(fieldName string) (FieldFilter, bool) {
	subFilter, ok := m[fieldName]
	if !ok {
		return MaskInverse{}, !strings.HasPrefix(fieldName, "XXX_")
	}
	if subFilter == nil {
		return nil, false
	}
	return subFilter, !subFilter.IsEmpty()
}

func (m MaskInverse) IsEmpty() bool {
	return len(m) == 0
}

func (m MaskInverse) String() string {
	return mapToString(m)
}

func MaskFromProtoFieldMask(
	fm *field_mask.FieldMask,
	naming func(string) string,
) (Mask, error) {
	return MaskFromPaths(fm.GetPaths(), naming)
}

func MaskInverseFromProtoFieldMask(
	fm *field_mask.FieldMask,
	naming func(string) string,
) (MaskInverse, error) {
	return MaskInverseFromPaths(fm.GetPaths(), naming)
}

func MaskFromPaths(paths []string, naming func(string) string) (Mask, error) {
	mask, err := FieldFilterFromPaths(paths, naming, func() FieldFilterContainer {
		return make(Mask)
	})
	if mask != nil {
		return mask.(Mask), err
	}
	return nil, err
}

func MaskInverseFromPaths(
	paths []string,
	naming func(string) string,
) (MaskInverse, error) {
	mask, err := FieldFilterFromPaths(paths, naming, func() FieldFilterContainer {
		return make(MaskInverse)
	})
	if mask != nil {
		return mask.(MaskInverse), err
	}
	return nil, err
}

func FieldFilterFromPaths(
	paths []string,
	naming func(string) string,
	filter func() FieldFilterContainer,
) (FieldFilterContainer, error) {
	root := filter()
	for _, path := range paths {
		mask := root
		for _, fieldName := range strings.Split(path, ".") {
			if fieldName == "" {
				return nil, errors.Errorf(
					"invalid fieldName FieldFilter format: \"%s\"",
					path,
				)
			}
			newFieldName := naming(fieldName)
			subNode, ok := mask.Get(newFieldName)
			if !ok {
				mask.Set(newFieldName, filter())
				subNode, _ = mask.Get(newFieldName)
			}
			mask = subNode
		}
	}
	return root, nil
}

func MaskFromString(s string) Mask {
	return FieldFilterFromString(s, func() FieldFilterContainer {
		return make(Mask)
	}).(Mask)
}

func MaskInverseFromString(s string) MaskInverse {
	return FieldFilterFromString(s, func() FieldFilterContainer {
		return make(MaskInverse)
	}).(MaskInverse)
}

func FieldFilterFromString(
	input string,
	filter func() FieldFilterContainer,
) FieldFilterContainer {
	var fieldName []string
	mask := filter()
	masks := []FieldFilterContainer{mask}
	for pos, r := range input {
		char := string(r)
		switch char {
		case " ", "\n", "\t":
		// Skip white spaces.

		case ",":
			if len(fieldName) != 0 {
				mask.Set(strings.Join(fieldName, ""), filter())
				fieldName = nil
			}

		case "{":
			if len(fieldName) == 0 {
				panic(
					fmt.Sprintf(
						"invalid mask format at position %d: got '{', expected a character",
						pos,
					),
				)
			}
			subMask := filter()
			mask.Set(strings.Join(fieldName, ""), subMask)
			fieldName = nil
			masks = append(masks, mask)
			mask = subMask

		case "}":
			if len(fieldName) != 0 {
				mask.Set(strings.Join(fieldName, ""), filter())
				fieldName = nil
			}
			mask = masks[len(masks)-1]
			masks = masks[:len(masks)-1]

		default:
			fieldName = append(fieldName, char)
		}
	}
	if len(fieldName) != 0 {
		mask.Set(strings.Join(fieldName, ""), filter())
	}
	return mask
}
