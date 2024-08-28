package util

//SliceContainsString SliceContainsString
func SliceContainsString(slc []string, el string) bool {
	for _, v := range slc {
		if v == el {
			return true
		}
	}
	return false
}
