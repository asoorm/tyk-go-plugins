package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/spf13/viper"
	"github.com/square/go-jose"
)

type jwksTmpl struct {
	Kid string   `json:"kid,omitempty"`
	Kty string   `json:"kty,omitempty"`
	Alg string   `json:"alg,omitempty"`
	Use string   `json:"use,omitempty"`
	N   string   `json:"n,omitempty"`
	E   string   `json:"e,omitempty"`
	X5C []string `json:"x5c,omitempty"`
}

type jsonWebKeys struct {
	Keys []jwksTmpl `json:"keys"`
}

var (
	db = cache.New(60*time.Minute, time.Minute)
)

type conf struct {
	Address string   `mapstructure:"address"`
	JWKSUri string   `mapstructure:"jwks_uri"`
	Merge   []string `mapstructure:"merge"`
}

func main() {
	vConf := viper.New()
	vConf.SetConfigType("yaml")
	vConf.SetConfigFile("config.yaml")
	err := vConf.ReadInConfig()
	fatalOnError(err, "unable to read config file")

	appConf := &conf{}
	err = vConf.Unmarshal(appConf)
	fatalOnError(err, "unable to unmarshal config file")

	if len(appConf.Merge) == 0 {
		fatalOnError(errors.New("no jwks_uris in merge array"), "merge array validation error")
	}

	http.Handle(appConf.JWKSUri, MergeJWKSHandler(appConf.Merge))

	writeLog("starting server on: %s", appConf.Address)
	err = http.ListenAndServe(":9000", nil)
	fatalOnError(err, "unable to start listener")
}

func fatalOnError(err error, format string, args ...interface{}) {
	if err != nil {
		writeLog(format+": %s", append(args, err.Error())...)
		os.Exit(1)
	}
}

func writeLog(format string, args ...interface{}) {
	if len(args) == 0 {
		_, _ = fmt.Fprint(os.Stdout, format+"\n")
		return
	}

	_, _ = fmt.Fprintf(os.Stdout, format+"\n", args...)
}

func MergeJWKSHandler(jwksUris []string) http.HandlerFunc {

	var mergedJWKSObject jsonWebKeys
	jwksUri, found := db.Get("jwks_uri")
	if !found {
		// limit concurrency to the number of CPUs
		resultArray := boundedParallelGet(jwksUris, runtime.NumCPU())

		for _, result := range resultArray {
			if result.err != nil {
				// log the error and continue to the next one
				writeLog("one of the jwks endpoints failed, skipping: %s", result.err.Error())
				continue
			}

			if result.res.StatusCode != http.StatusOK {
				writeLog("one of the jwks endpoints returned non-200, skipping: %d", result.res.StatusCode)
				continue
			}

			bodyBytes, err := ioutil.ReadAll(result.res.Body)
			if err != nil {
				result.res.Body.Close()
				writeLog("unable to read body, skipping: %s", err.Error())
				continue
			}
			result.res.Body.Close()

			jsonWebKeySetJOSE := &jose.JSONWebKeySet{}
			json.Unmarshal(bodyBytes, jsonWebKeySetJOSE)

			keys := TranslateJWKSet(jsonWebKeySetJOSE)

			mergedJWKSObject.Keys = append(mergedJWKSObject.Keys, keys...)
		}

		db.Set("jwks_uri", mergedJWKSObject, 60*time.Minute)
	}

	if found {
		mergedJWKSObject = jwksUri.(jsonWebKeys)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		resBytes, _ := json.Marshal(mergedJWKSObject)
		w.WriteHeader(http.StatusOK)
		w.Write(resBytes)
	}
}

func TranslateJWKSet(in *jose.JSONWebKeySet) []jwksTmpl {
	var keys []jwksTmpl
	for _, v := range in.Keys {
		switch key := v.Key.(type) {
		case *rsa.PublicKey:
			// throw away non signing public key
			if v.Use != "sig" {
				continue
			}
			x509Bytes := x509.MarshalPKCS1PublicKey(key)

			// make a big enough byte slice
			e := make([]byte, 8)
			// fill it
			binary.BigEndian.PutUint64(e, uint64(key.E))
			// trim buffer of null values
			e = bytes.TrimLeft(e, "\x00")

			keys = append(keys, jwksTmpl{
				Kid: v.KeyID,
				Kty: "RSA",
				Alg: v.Algorithm,
				Use: v.Use,
				N:   strings.TrimRight(base64.URLEncoding.EncodeToString(key.N.Bytes()), "="),
				E:   strings.TrimRight(base64.URLEncoding.EncodeToString(e), "="),
				X5C: []string{strings.TrimRight(base64.StdEncoding.EncodeToString(x509Bytes), "=")},
			})
		}
	}

	return keys
}

// a struct to hold the result from each request including an index
// which will be used for sorting the results after they come in
type result struct {
	index int
	res   *http.Response
	err   error
}

// boundedParallelGet sends requests in parallel but only up to a certain
// limit, and furthermore it's only parallel up to the amount of CPUs but
// is always concurrent up to the concurrency limit
// src: https://gist.github.com/montanaflynn/ea4b92ed640f790c4b9cee36046a5383
func boundedParallelGet(urls []string, concurrencyLimit int) []result {
	// this buffered channel will block at the concurrency limit
	semaphoreChan := make(chan struct{}, concurrencyLimit)

	// this channel will not block and collect the http request results
	resultsChan := make(chan *result)

	// make sure we close these channels when we're done with them
	defer func() {
		close(semaphoreChan)
		close(resultsChan)
	}()

	// keen an index and loop through every url we will send a request to
	for i, url := range urls {

		// start a go routine with the index and url in a closure
		go func(i int, url string) {

			// this sends an empty struct into the semaphoreChan which
			// is basically saying add one to the limit, but when the
			// limit has been reached block until there is room
			semaphoreChan <- struct{}{}

			// send the request and put the response in a result struct
			// along with the index so we can sort them later along with
			// any error that might have occoured
			res, err := http.Get(url)
			result := &result{i, res, err}

			// now we can send the result struct through the resultsChan
			resultsChan <- result

			// once we're done it's we read from the semaphoreChan which
			// has the effect of removing one from the limit and allowing
			// another goroutine to start
			<-semaphoreChan

		}(i, url)
	}

	// make a slice to hold the results we're expecting
	var results []result

	// start listening for any results over the resultsChan
	// once we get a result append it to the result slice
	for {
		result := <-resultsChan
		results = append(results, *result)

		// if we've reached the expected amount of urls then stop
		if len(results) == len(urls) {
			break
		}
	}

	// let's sort these results real quick
	sort.Slice(results, func(i, j int) bool {
		return results[i].index < results[j].index
	})

	// now we're done we return the results
	return results
}
