#compile command:
" gcc my_httpserver.c tdate_parse.c match.c -o my_http -I ./ "
#how to run the project
"./my_http -p 8001"
#how to test on browser
enter "<linux IP>:8001"

#note
support linux only. currently support mime type listed below
if you want more support, modify this array:
static struct mime_entry typ_tab[] = {
	{ "a", 0, "application/octet-stream", 0 },
	{ "bin", 0, "application/octet-stream", 0 },
	{ "css", 0, "text/css", 0 },
	{ "exe", 0, "application/octet-stream", 0 },
 	{ "htm", 0, "text/html; charset=%s", 0 },
        { "html", 0, "text/html; charset=%s", 0 },
	{ "jpg", 0, "image/jpeg", 0 },
	{ "js", 0, "application/x-javascript", 0 },
	{ "mp3", 0, "audio/mpeg", 0 },
 	{ "mp4", 0, "video/mp4", 0 },
};
