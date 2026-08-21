package render

import "html/template"

func Bio(userBio string) template.HTML {
	return template.HTML(userBio)
}
