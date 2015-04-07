files = LICENSE README.md readme.txt security_headers.php
all : $(files)
	zip security_headers.zip $(files)
