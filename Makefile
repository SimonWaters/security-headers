files = LICENSE README.md readme.txt security_headers.php
all : $(files)
	tar cvf security_headers.zip $(files)
