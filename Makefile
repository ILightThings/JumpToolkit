build:
	echo "Compiling for current platform"
    go build -o bin/jump_ptr_lookup src/jump_ptr_lookup/jump_ptr_lookup.go
   	go build -o bin/jump_port_scan src/jump_port_scan/jump_port_scan.go

windows:
	echo "Compiling for Windows AMD64"
    GOOS=windows GOARCH=amd64 go build -o bin/jump_ptr_lookup.exe src/jump_ptr_lookup/jump_ptr_lookup.go
    GOOS=windows GOARCH=amd64 go build -o bin/jump_port_scan.exe src/jump_port_scan/jump_port_scan.go
