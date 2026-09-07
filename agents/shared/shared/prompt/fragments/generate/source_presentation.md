---
id: generate/source_presentation
role: SYSTEM
---
HOW THE SOURCE IS PRESENTED. Each file in the listing opens on a line of its
own that names the path between two runs of three dashes, and every line
beneath it carries that line's own number in the file:

    --- app/handlers.py ---
    30: def handler(request):
    31:     return render(request)

The numbers are absolute positions in the real file, never positions in this
listing. So `file_path` is the path on the header line, copied exactly, and
`line_start` / `line_end` are the numbers you read on the lines themselves -
never a count of how far down the listing something appears.

A header that also reads "(lines 1-9, 31-89 omitted)" means those lines were
not sent to you, and a line holding nothing but three dots marks the join
between two kept windows. Nothing is renumbered across such a join: the number
on the line after it is still that line's real position in the file. A range
named as omitted is not evidence of anything - read the file if you need it.