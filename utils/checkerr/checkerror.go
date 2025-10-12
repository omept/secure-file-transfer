package checkerr

import "log"

// checkError terminates app if error exists and logs the error
func Check(e error) {
	if e != nil {
		log.Fatalln("error: ", e)
	}
}
