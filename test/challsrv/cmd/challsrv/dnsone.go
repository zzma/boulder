package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

func (srv *managementServer) addDNS01(w http.ResponseWriter, r *http.Request) {
	msg, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var request struct {
		Host  string
		Value string
	}
	err = json.Unmarshal(msg, &request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if request.Host == "" || request.Value == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	srv.challSrv.AddDNSOneChallenge(request.Host, request.Value)
	fmt.Printf("Added DNS-01 TXT challenge for Host %q - Value %q\n",
		request.Host, request.Value)
	w.WriteHeader(http.StatusOK)
}

func (srv *managementServer) delDNS01(w http.ResponseWriter, r *http.Request) {
	msg, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var request struct {
		Host string
	}
	err = json.Unmarshal(msg, &request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if request.Host == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	srv.challSrv.DeleteDNSOneChallenge(request.Host)
	fmt.Printf("Removed DNS-01 TXT challenge for Host %q\n", request.Host)
	w.WriteHeader(http.StatusOK)
}
