# NOTE
We originally got decryption working after mulitple days of work, however somewhere when merging our changes together and creating a real menu system we managed to break our decryption and encryption.

To show that we had encryption / decryption working, I've prepared a branch that has those old commits, that you can see here: https://github.com/joshuajz/Cryptography-468-/tree/decryption-works-here

# Install Instructions
To download missing packages in GO, you simply run `go build`, and you should then be able to execute the program using `go run main.go`

For python, you need to download 2 main dependencies using pip:
- `pip3 install zeroconf`
- `pip3 install pycryptodome`
