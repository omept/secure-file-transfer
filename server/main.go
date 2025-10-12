package main

import (
	"crypto/aes"
	"crypto/cipher"
	"io"
	"log"
	"net"
	"os"

	"github.com/joho/godotenv"
	"github.com/omept/secure-file-transfer/utils/checkerr"
)

func main() {

	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file") // create a .env file with the attached .env.example as template
	}

	if len(os.Args) != 2 {
		log.Fatalf("required format %s address:port\n", os.Args[0])
	}

	//validate address:port structure
	addr, err := net.ResolveTCPAddr("tcp", os.Args[1])
	checkerr.Check(err)
	// instantiate listener
	listener, err := net.ListenTCP("tcp", addr)
	checkerr.Check(err)
	defer listener.Close()

	//start server and serve encrypted file
	start(listener)

}

// start listens to tcp connections and serves  from file to connected clients
func start(listerner *net.TCPListener) {
	log.Println("🚀 Server listenening on ", listerner.Addr().String())
	for {
		conn, err := listerner.Accept()
		if err != nil {
			log.Println("error: ", err)
			continue
		}
		go processConnection(conn)
	}
}

// processConnection serves the data to the client and closes the connection when done
func processConnection(conn net.Conn) {
	defer func(conn net.Conn) {
		log.Println("server disconnecting from ", conn.RemoteAddr().String())
		conn.Close()
		log.Println("server disconnected.")
	}(conn)

	fileName := os.Getenv("FILE_NAME")
	file, err := os.Open(fileName)
	if err != nil {
		log.Println("error: ", err)
	}
	defer file.Close()
	log.Println("server connected to ", conn.RemoteAddr().String())

	key := os.Getenv("ENCRYPT_DECRYPT_KEY") // key lenght of 32 to use AES-256
	var fileHolder [1024 * 10]byte          // read chuncks of 1024 * 10 bytes (10kb) from the file
	total := 0
	for {
		n, err := file.Read(fileHolder[:])
		if n == 0 {
			break
		}
		log.Printf("read %d bytes from file\n", n)
		if err == io.EOF {
			// encrypt and send chunk
			handleVideoChunk(key, fileHolder[0:n], conn)
			break
		}
		// encrypt and send chunk
		nn := handleVideoChunk(key, fileHolder[0:n], conn)
		total += nn
		log.Printf("encrypted and wrote %d bytes to %s\n", nn, conn.RemoteAddr())
	}
	log.Printf("✅ File completly encrypted and total of %d bytes sent to client at  %s\n", total, conn.RemoteAddr())

}

// handleVideoChunk uses the encryption key to encryt byte slices of the data and write to connection
func handleVideoChunk(key string, data []byte, conn net.Conn) int {
	secureBytes, err := encrypt(data, key) // this modifies the size of the chunk
	if err != nil {
		log.Println("error: ", err)
		return 0
	}
	n, _ := conn.Write(secureBytes)
	return n
}

// encrypt takes a byte slice and encrypts with AES
func encrypt(data []byte, passphrase string) ([]byte, error) {
	block, err := aes.NewCipher([]byte(passphrase))
	if err != nil {
		return []byte{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return []byte{}, err
	}
	nonce := make([]byte, gcm.NonceSize())
	cipherBytes := gcm.Seal(nonce, nonce, data, nil)
	return cipherBytes, nil
}
