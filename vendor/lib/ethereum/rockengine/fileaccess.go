package rockengine

import (
	"log"
	"os"
  "io/ioutil"
)

func ReadFile(filePath string) (data []byte, permissions os.FileMode) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
    log.Fatal(err)
    panic(err)
  }
	permissions = CheckPermissions(filePath)
	return
}

func CheckPermissions(filePath string) (permissions os.FileMode) {
  fileInfo, err := os.Stat(filePath)
  if err != nil {
      log.Fatal(err)
  }
  permissions = fileInfo.Mode()
  return permissions
}

func ChangeReadOnly(filePath string) { // Assign READ ONLY permission to filePath
  err := os.Chmod(filePath, 0555)
  if err != nil {
    log.Println(err)
  } else {
    log.Println("File has read only permission")
  }
}

func ChangeReadWrite(filePath string) { // Assign READ & WRITE permission to filePath
  err := os.Chmod(filePath, 0777)
  if err != nil {
    log.Println(err)
  } else {
    log.Println("File has read/write permission")
  }
}
