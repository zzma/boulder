package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

func (srv *managementServer) addHTTP01(w http.ResponseWriter, r *http.Request) {
	msg, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var request struct {
		Token   string
		Content string
	}
	err = json.Unmarshal(msg, &request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if request.Token == "" || request.Content == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	srv.challSrv.AddHTTPOneChallenge(request.Token, request.Content)
	fmt.Printf("Added HTTP-01 challenge for token %q - key auth %q\n",
		request.Token, request.Content)
	w.WriteHeader(http.StatusOK)
}

func (srv *managementServer) delHTTP01(w http.ResponseWriter, r *http.Request) {
	msg, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var request struct {
		Token string
	}
	err = json.Unmarshal(msg, &request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if request.Token == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	srv.challSrv.DeleteHTTPOneChallenge(request.Token)
	fmt.Printf("Removed HTTP-01 challenge for token %q\n", request.Token)
	w.WriteHeader(http.StatusOK)
}
