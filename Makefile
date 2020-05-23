all: mesh mesh2

mesh: mesh.c
	gcc -o mesh -Wall -g mesh.c
mesh2: mesh.c
	gcc -o mesh2 -DMAGIC2 -Wall -g mesh.c
