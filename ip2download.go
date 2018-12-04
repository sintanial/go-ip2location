package ip2location

import (
	"os"
	"io"
	"net/http"
	"fmt"
	"strings"
	"io/ioutil"
)

func DownloadDBToWriter(token, dbcode string, to io.Writer) error {
	resp, err := http.Get(fmt.Sprintf("https://www.ip2location.com/download/?token=%s&file=%s", token, dbcode))
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("invalid response status code %v", resp.StatusCode)
	}

	if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") || resp.ContentLength < 100 {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		return fmt.Errorf("server response error '%v'", string(body))
	}

	_, err = io.Copy(to, resp.Body)
	return err
}

func DownloadDBToFile(token, dbcode string, to string) error {
	f, err := os.Create(to)
	if err != nil {
		return err
	}
	defer f.Close()

	return DownloadDBToWriter(token, dbcode, f)
}

func DownloadDBToTmp(token, dbcode string) (*os.File, error) {
	f, err := ioutil.TempFile("", "ip2location.zip")
	if err != nil {
		return nil, err
	}

	return f, DownloadDBToWriter(token, dbcode, f)
}
