build:
	go mod tidy
	go build -o jfcrypt

install:
	install -m 755 jfcrypt /usr/local/bin

clean:
	rm jfcrypt
	rm go.sum
