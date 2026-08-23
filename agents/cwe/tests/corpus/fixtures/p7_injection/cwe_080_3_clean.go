package render

import "html/template"

func Bio(userBio string) string {
	return template.HTMLEscapeString(userBio)
}
