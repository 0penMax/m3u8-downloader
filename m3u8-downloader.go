package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// Request header timeout
	HEAD_TIMEOUT = 15 * time.Second
	// Progress bar length
	PROGRESS_WIDTH = 30
	// ts video clip naming rules
	TS_NAME_TEMPLATE = "%05d.ts"
)

var (
	// command-line parameter
	urlFlag    = flag.String("u", "", "m3u8 download address (http(s)://url/xx/xx/index.m3u8)")
	nFlag      = flag.Int("n", 4, "num:Number of download threads (default 4)")
	htAutoFlag = flag.Bool("htAuto", true, "Automatic try hostType V2, if V1 return error")
	htFlag     = flag.String("ht", "v1", "HostType: set the way to getHost (v1: `http(s):// + url.Host + filepath.Dir(url.Path)`; v2: `http(s)://+ u. Host`)")
	oFlag      = flag.String("o", fmt.Sprintf("movie-%d", time.Now().Unix()), "movieName:Customized filename (defaults to movie) without a suffix")
	cFlag      = flag.String("c", "", "cookie:Customizing request cookies")
	sFlag      = flag.Int("s", 0, "InsecureSkipVerify:Whether to allow insecure requests (default 0)")
	spFlag     = flag.String("sp", "", "savePath:The absolute path of the file (default is the current path, default is recommended).")

	logger *log.Logger
)

var httpClient *http.Client
var defaultHeaders = map[string]string{
	"User-Agent":      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6)",
	"Connection":      "keep-alive",
	"Accept":          "*/*",
	"Accept-Encoding": "*",
	"Accept-Language": "en-US,zh;q=0.9,en;q=0.8",
}

// TsInfo Used to save the download address and filename of the ts file
type TsInfo struct {
	Name string
	Url  string
}

func init() {
	logger = log.New(os.Stdout, "", 0)
}

func main() {
	msgTpl := "[Function]:Multi-threaded download of live streaming m3u8 video  \n [Reminder]:Download failed, m3u8 address may be nested"
	fmt.Println(msgTpl)
	runtime.GOMAXPROCS(runtime.NumCPU())

	// 1. Parsing command line parameters
	flag.Parse()
	m3u8Url := *urlFlag
	movieName := *oFlag
	insecure := *sFlag

	args := flag.Args()
	if len(args) == 2 {
		m3u8Url = args[0]
		movieName = args[1]
	} else if len(args) == 1 {
		m3u8Url = args[0]
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure != 0},
	}

	httpClient = &http.Client{
		Timeout:   HEAD_TIMEOUT,
		Transport: transport,
	}

	if !strings.HasPrefix(m3u8Url, "http") || m3u8Url == "" {
		flag.Usage()
		return
	}

	conf := config{
		url:           m3u8Url,
		maxGoroutines: *nFlag,
		hostType:      *htFlag,
		movieName:     movieName,
		cookie:        *cFlag,
		savePath:      *spFlag,
	}

	err := Run(conf)

	switch {
	case errors.Is(err, errDownload):
		logger.Println("download failed with err:", err)
		if *htAutoFlag && *htFlag != "v2" {
			logger.Println("Try HostType V2")
			conf.hostType = "v2"
			err = Run(conf)
			if err != nil {
				logger.Println(err)
			}
		}

	case err == nil:
	default:
		log.Println(err)
	}

}

var errDownload = errors.New("download failed")

type config struct {
	cookie        string
	url           string
	hostType      string
	savePath      string
	movieName     string
	maxGoroutines int
}

func Run(c config) error {
	now := time.Now()
	// dynamic headers
	host, err := getHost(c.url, c.hostType)
	if err != nil {
		return err
	}
	defaultHeaders["Referer"] = host
	defaultHeaders["Cookie"] = c.cookie

	var downloadDir string
	pwd, _ := os.Getwd()
	if c.savePath != "" {
		pwd = c.savePath
	} else {
		df, err := getDownloadsFolder()
		if err != nil {
			return err
		}
		pwd = df
	}

	// Initialize the directory for downloading ts, where all later ts files will be saved.
	downloadDir = filepath.Join(pwd, c.movieName)
	if isExist, _ := pathExists(downloadDir); !isExist {
		os.MkdirAll(downloadDir, os.ModePerm)
	}

	cleanTempFilesFunc := func() {
		//Automatic clearing of the ts file directory
		os.RemoveAll(downloadDir)
		log.Println("auto cleaned temp files")
	}

	defer cleanTempFilesFunc()

	// 2. Parse m3u8
	m3u8Host, err := getHost(c.url, c.hostType)
	if err != nil {
		return err
	}
	m3u8Body, err := getM3u8Body(c.url)
	if err != nil {
		return err
	}
	tsKey, err := getM3u8Key(m3u8Host, m3u8Body)
	if err != nil {
		return err
	}
	if tsKey != "" {
		fmt.Printf("ts file key to be decrypted : %s \n", tsKey)
	}
	tsList := getTsList(m3u8Host, m3u8Body)
	fmt.Println("Number of ts files to be downloaded:", len(tsList))

	// 3. Download ts file to downloadDir
	err = downloader(tsList, c.maxGoroutines, downloadDir, tsKey)
	if err != nil {
		log.Println()
		log.Println(err)
		return errDownload
	}
	if ok := checkTsDownDir(downloadDir); !ok {
		return errors.New(fmt.Sprintf("\n[Failed] Please check the validity of the url address \n"))
	}

	// 4. Merge ts cut files into mp4 files
	mv, err := mergeTs(downloadDir)
	if err != nil {
		return err
	}

	//5. Output download video information
	DrawProgressBar("Merging", float32(1), PROGRESS_WIDTH, mv)
	fmt.Printf("\n[Success] Download Save Path：%s | total duration: %6.2fs\n", mv, time.Now().Sub(now).Seconds())
	return nil
}

func httpGet(url string) ([]byte, int, http.Header, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, 0, nil, err
	}

	for k, v := range defaultHeaders {
		req.Header.Set(k, v)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, 0, nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	return body, resp.StatusCode, resp.Header, err
}

// Get the host of the m3u8 address
func getHost(Url, ht string) (host string, err error) {
	u, err := url.Parse(Url)
	if err != nil {
		return "", err
	}
	switch ht {
	case "v1":
		host = u.Scheme + "://" + u.Host + filepath.Dir(u.EscapedPath())
	case "v2":
		host = u.Scheme + "://" + u.Host
	}
	return
}

// Get the content body of the m3u8 address
func getM3u8Body(Url string) (string, error) {
	body, _, _, err := httpGet(Url)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// Get key for m3u8 encryption
func getM3u8Key(host, html string) (key string, err error) {
	lines := strings.Split(html, "\n")
	key = ""
	for _, line := range lines {
		if strings.Contains(line, "#EXT-X-KEY") {
			uri_pos := strings.Index(line, "URI")
			quotation_mark_pos := strings.LastIndex(line, "\"")
			key_url := strings.Split(line[uri_pos:quotation_mark_pos], "\"")[1]
			if !strings.Contains(line, "http") {
				key_url = fmt.Sprintf("%s/%s", host, key_url)
			}
			resBody, status, _, err := httpGet(key_url)
			if err != nil {
				return "", err
			}
			if status == 200 {
				key = string(resBody)
			}
		}
	}
	return
}

func getTsList(host, body string) (tsList []TsInfo) {
	lines := strings.Split(body, "\n")
	index := 0
	var ts TsInfo

	// Normalize host: replace backslashes and trim trailing slash
	host = strings.ReplaceAll(host, "\\", "/")
	host = strings.TrimRight(host, "/")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Normalize line: replace backslashes with forward slashes
		line = strings.ReplaceAll(line, "\\", "/")

		index++
		var url string
		if strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") {
			url = line
		} else {
			// Ensure we don't produce double slashes when joining
			if strings.HasPrefix(line, "/") {
				url = host + line
			} else {
				url = host + "/" + line
			}
		}

		ts = TsInfo{
			Name: fmt.Sprintf(TS_NAME_TEMPLATE, index),
			Url:  url,
		}
		tsList = append(tsList, ts)
	}
	return
}

// Download ts file
// @modify: 2020-08-13 Fix the problem that SyncByte merge in ts format can't be played.
func downloadTsFile(ts TsInfo, download_dir, key string, retries int, fail *bool) {
	defer func() {
		if r := recover(); r != nil {
			downloadTsFile(ts, download_dir, key, retries-1, fail)
		}
	}()
	curr_path_file := fmt.Sprintf("%s/%s", download_dir, ts.Name)
	if isExist, _ := pathExists(curr_path_file); isExist {
		//logger.Println("[warn] File: " + ts.Name + "already exist")
		return
	}
	body, status, headers, err := httpGet(ts.Url)
	if err != nil || status != 200 {
		if retries > 0 {
			downloadTsFile(ts, download_dir, key, retries-1, fail)
		} else {
			logger.Printf("\n[error] File: %s\n", ts.Url)
			logger.Println("status code:", status)
			logger.Println(err)
			*fail = true
		}
		return
	}
	// Checksum length for legality
	var origData []byte
	origData = body
	contentLen := 0
	contentLenStr := headers.Get("Content-Length")
	if contentLenStr != "" {
		contentLen, _ = strconv.Atoi(contentLenStr)
	}
	if len(origData) == 0 || (contentLen > 0 && len(origData) < contentLen) || err != nil {
		if retries > 0 {
			downloadTsFile(ts, download_dir, key, retries-1, fail)
		} else {
			logger.Println("\n[error] File: "+ts.Name+" res origData invalid or err：", err)
			*fail = true
		}
		return
	}
	// Decrypting out video ts source files
	if key != "" {
		//Decrypt ts file, algorithm: aes 128 cbc pack5
		origData, err = AesDecrypt(origData, []byte(key))
		if err != nil {
			if retries > 0 {
				downloadTsFile(ts, download_dir, key, retries-1, fail)
				return
			} else {
				logger.Println("[error] File decryption: " + err.Error())
				*fail = true
			}
			return
		}
	}
	// https://en.wikipedia.org/wiki/MPEG_transport_stream
	// Some TS files do not start with SyncByte 0x47, they can not be played after merging,
	// Need to remove the bytes before the SyncByte 0x47(71).
	syncByte := uint8(71) //0x47
	bLen := len(origData)
	for j := 0; j < bLen; j++ {
		if origData[j] == syncByte {
			origData = origData[j:]
			break
		}
	}
	err = os.WriteFile(curr_path_file, origData, 0666)
	if err != nil {
		logger.Println(err)
	}
}

// downloader m3u8
func downloader(tsList []TsInfo, maxGoroutines int, downloadDir string, key string) error {
	retry := 5 //Number of retries for a single ts download
	var wg sync.WaitGroup
	limiter := make(chan struct{}, maxGoroutines) //chan struct memory occupied 0 bool occupied 1
	tsLen := len(tsList)
	downloadCount := 0
	var tsDownloadFail bool = false
	for _, ts := range tsList {
		wg.Add(1)
		limiter <- struct{}{}
		go func(ts TsInfo, downloadDir, key string, retryies int, fail *bool) {
			defer func() {
				wg.Done()
				<-limiter
			}()
			downloadTsFile(ts, downloadDir, key, retryies, fail)
			if !tsDownloadFail {
				downloadCount++
				DrawProgressBar("Downloading", float32(downloadCount)/float32(tsLen), PROGRESS_WIDTH, ts.Name)
			}
			return
		}(ts, downloadDir, key, retry, &tsDownloadFail)
		if tsDownloadFail {
			break
		}
	}
	wg.Wait()
	if tsDownloadFail {
		return errors.New("download fail")
	}

	return nil
}

func checkTsDownDir(dir string) bool {
	if isExist, _ := pathExists(filepath.Join(dir, fmt.Sprintf(TS_NAME_TEMPLATE, 0))); !isExist {
		return true
	}
	return false
}

// Merge ts file
func mergeTs(downloadDir string) (string, error) {
	mvName := downloadDir + ".mp4"
	outMv, _ := os.Create(mvName)
	defer outMv.Close()
	writer := bufio.NewWriter(outMv)
	err := filepath.Walk(downloadDir, func(path string, f os.FileInfo, err error) error {
		if f == nil {
			return err
		}
		if f.IsDir() || filepath.Ext(path) != ".ts" {
			return nil
		}
		bytes, _ := ioutil.ReadFile(path)
		_, err = writer.Write(bytes)
		return err
	})
	if err != nil {
		return "", err
	}
	_ = writer.Flush()
	return mvName, nil
}

// progress bar
func DrawProgressBar(prefix string, proportion float32, width int, suffix ...string) {
	pos := int(proportion * float32(width))
	s := fmt.Sprintf("[%s] %s%*s %6.2f%% \t%s",
		prefix, strings.Repeat("■", pos), width-pos, "", proportion*100, strings.Join(suffix, ""))
	fmt.Print("\r" + s)
}

// Determine if a file exists
func pathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func AesEncrypt(origData, key []byte, ivs ...[]byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	var iv []byte
	if len(ivs) == 0 {
		iv = key
	} else {
		iv = ivs[0]
	}
	origData = PKCS7Padding(origData, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, iv[:blockSize])
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	return crypted, nil
}

func AesDecrypt(crypted, key []byte, ivs ...[]byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	var iv []byte
	if len(ivs) == 0 {
		iv = key
	} else {
		iv = ivs[0]
	}
	blockMode := cipher.NewCBCDecrypter(block, iv[:blockSize])
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	origData = PKCS7UnPadding(origData)
	return origData, nil
}

func getDownloadsFolder() (string, error) {
	var downloadsPath string

	switch runtime.GOOS {
	case "windows":
		// On Windows, use the USERPROFILE environment variable
		homeDir, exists := os.LookupEnv("USERPROFILE")
		if !exists {
			return "", fmt.Errorf("could not determine home directory")
		}
		downloadsPath = filepath.Join(homeDir, "Downloads")
	case "darwin":
		// On macOS, use the HOME environment variable
		homeDir, exists := os.LookupEnv("HOME")
		if !exists {
			return "", fmt.Errorf("could not determine home directory")
		}
		downloadsPath = filepath.Join(homeDir, "Downloads")
	case "linux":
		// On Linux, use XDG_DOWNLOAD_DIR or default to ~/Downloads
		xdgDownloadsDir, exists := os.LookupEnv("XDG_DOWNLOAD_DIR")
		if exists {
			downloadsPath = xdgDownloadsDir
		} else {
			homeDir, exists := os.LookupEnv("HOME")
			if !exists {
				return "", fmt.Errorf("could not determine home directory")
			}
			downloadsPath = filepath.Join(homeDir, "Downloads")
		}
	default:
		return "", fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}

	return downloadsPath, nil
}
