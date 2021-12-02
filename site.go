package main

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"text/template"

	"golang.org/x/crypto/ocsp"
)

var (
	homeHTML       []byte
	loginTrueHTML  []byte
	loginFalseHTML []byte
	// trustedCertificates       *x509.CertPool
	verifyCertificationOption *x509.VerifyOptions
	// permittedKeyUsages           []x509.ExtKeyUsage
	trustedCertificatesNames []string
	errMissingCertificate    error = errors.New("Nenhum certificado digital recebido.")
	// errCertificateCARootNotTrust error = errors.New("O certificado informado é assinado por uma Authoridade certificadora Raiz não confiavel.")
	// errCertificateRevocated      error = errors.New("O certificado informado foi revogado.")
	// errCertificateDateExpired    error = errors.New("O certificado informado está com a data expirada.")
	// errCertificateDateInvalid    error = errors.New("O certificado informado está com a data invalida.")
)

type UserDatails struct {
	Name               string
	Email              string
	Organisation       string
	OrganisationalUnit string
	Country            string
	State              string
	City               string
}

type BadClientCertificate struct {
	Error       string
	CARootNames []string
}

// https://stackoverflow.com/questions/46626963/golang-sending-ocsp-request-returns
func isCertificateRevokedByOCSP(commonName string, clientCert, issuerCert *x509.Certificate, ocspServer string) (bool, error) {
	opts := &ocsp.RequestOptions{Hash: crypto.SHA1}
	buffer, err := ocsp.CreateRequest(clientCert, issuerCert, opts)
	if err != nil {
		return false, nil
	}
	httpRequest, err := http.NewRequest(http.MethodPost, ocspServer, bytes.NewBuffer(buffer))
	if err != nil {
		return false, nil
	}
	ocspUrl, err := url.Parse(ocspServer)
	if err != nil {
		return false, nil
	}
	httpRequest.Header.Add("Content-Type", "application/ocsp-request")
	httpRequest.Header.Add("Accept", "application/ocsp-response")
	httpRequest.Header.Add("host", ocspUrl.Host)
	httpClient := &http.Client{}
	httpResponse, err := httpClient.Do(httpRequest)
	if err != nil {
		return false, nil
	}
	defer httpResponse.Body.Close()
	output, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		return false, nil
	}
	ocspResponse, err := ocsp.ParseResponse(output, issuerCert)
	if err != nil {
		return false, nil
	}
	if ocspResponse.Status == ocsp.Revoked {
		err := fmt.Errorf("certificate '%s' has been revoked by OCSP server %s, refusing connection", commonName, ocspServer)
		return true, err
	} else {
		return false, nil
	}
}

func Home(w http.ResponseWriter, r *http.Request) {
	w.Write(homeHTML)
}

func Login(w http.ResponseWriter, r *http.Request) {

	templateLoginTrue, err := template.New("LoginTrue").Parse(string(loginTrueHTML))
	templateLoginFalse, err := template.New("LoginFalse").Parse(string(loginFalseHTML))

	if err != nil {
		log.Panic(err)
	}

	if len(r.TLS.PeerCertificates) > 0 {

		for _, certificate := range r.TLS.PeerCertificates {

			_, err := certificate.Verify(*verifyCertificationOption)

			if err != nil {
				loginFalseHtml := &bytes.Buffer{}
				templateLoginFalse.Execute(loginFalseHtml, &BadClientCertificate{
					Error:       err.Error(),
					CARootNames: trustedCertificatesNames,
				})

				w.Header().Set("Connection", "Close")
				w.WriteHeader(401)
				w.Write(loginFalseHtml.Bytes())
				break
			}

			httpResponse, err := http.Get(certificate.IssuingCertificateURL[0])
			if err != nil {
				fmt.Println(err)
			}
			CAcertRAW, err := ioutil.ReadAll(httpResponse.Body)
			if err != nil {
				fmt.Println(err)
			}
			httpResponse.Body.Close()

			pemBlock, _ := pem.Decode(CAcertRAW)

			CACert := new(x509.Certificate)

			if pemBlock == nil {
				CACert, err = x509.ParseCertificate(CAcertRAW)
				if err != nil {
					fmt.Println(err, string(CAcertRAW))
				}
			} else {
				CACert, err = x509.ParseCertificate(pemBlock.Bytes)
				if err != nil {
					fmt.Println(err, string(CAcertRAW))
				}
			}

			isRevoked, err := isCertificateRevokedByOCSP(certificate.Subject.CommonName, certificate, CACert, certificate.OCSPServer[0])

			if isRevoked {
				loginFalseHtml := &bytes.Buffer{}
				templateLoginFalse.Execute(loginFalseHtml, &BadClientCertificate{
					Error:       err.Error(),
					CARootNames: trustedCertificatesNames,
				})

				w.Header().Set("Connection", "Close")
				w.WriteHeader(401)
				w.Write(loginFalseHtml.Bytes())
			} else {
				var certificateDetails UserDatails

				for _, email := range certificate.EmailAddresses {
					// fmt.Println("E-mail:", email)
					certificateDetails.Email = email
				}
				for _, nameValue := range certificate.Subject.Names {
					switch nameValue.Type.String() {
					case "2.5.4.6":
						// fmt.Println("Country:", nameValue.Value)
						certificateDetails.Country = fmt.Sprintf("%v", nameValue.Value)
					case "2.5.4.8":
						// fmt.Println("State:", nameValue.Value)
						certificateDetails.State = fmt.Sprintf("%v", nameValue.Value)
					case "2.5.4.7":
						// fmt.Println("City:", nameValue.Value)
						certificateDetails.City = fmt.Sprintf("%v", nameValue.Value)
					case "2.5.4.10":
						// fmt.Println("Organisation:", nameValue.Value)
						certificateDetails.Organisation = fmt.Sprintf("%v", nameValue.Value)
					case "2.5.4.11":
						// fmt.Println("Organisational Unit:", nameValue.Value)
						certificateDetails.OrganisationalUnit = fmt.Sprintf("%v", nameValue.Value)
					case "2.5.4.3":
						// fmt.Println("Name:", nameValue.Value)
						certificateDetails.Name = fmt.Sprintf("%v", nameValue.Value)
					}
				}

				loginTrueHtml := &bytes.Buffer{}
				templateLoginTrue.Execute(loginTrueHtml, certificateDetails)
				w.WriteHeader(200)
				w.Write(loginTrueHtml.Bytes())

			}
		}

	} else {
		// https://stackoverflow.com/questions/54143947/is-there-a-way-to-dynamically-trigger-ssl-tls-renegotiation-in-a-servlet
		loginFalseHtml := &bytes.Buffer{}
		templateLoginFalse.Execute(loginFalseHtml, &BadClientCertificate{
			Error:       errMissingCertificate.Error(),
			CARootNames: trustedCertificatesNames,
		})

		w.Header().Set("Connection", "Close")
		w.WriteHeader(401)
		w.Write(loginFalseHtml.Bytes())

	}
}
func init() {
	fileContent, err := os.ReadFile("templates/index.html")
	if err != nil {
		fmt.Println("Erro na leitura do arquivo index.html")
		log.Panic(err)
	}
	homeHTML = append(homeHTML, fileContent...)

	fileContent, err = os.ReadFile("templates/loginTrue.html")
	if err != nil {
		fmt.Println("Erro na leitura do arquivo loginTrue.html")
		log.Panic(err)
	}
	loginTrueHTML = append(loginTrueHTML, fileContent...)

	fileContent, err = os.ReadFile("templates/loginFalse.html")
	if err != nil {
		fmt.Println("Erro na leitura do arquivo loginFalse.html")
		log.Panic(err)
	}
	loginFalseHTML = append(loginFalseHTML, fileContent...)

	trustedCertificates := x509.NewCertPool()

	files, err := ioutil.ReadDir("./CAroot")
	if err != nil {
		fmt.Println("Não foi possivel listar certificados confiaveis.", err)
	}

	for _, file := range files {
		fileContent, err := os.ReadFile("./CAroot/" + file.Name())
		if err != nil {
			fmt.Println(err)
			continue
		}

		loadCertificateSucess := trustedCertificates.AppendCertsFromPEM(fileContent)
		pemBlock, _ := pem.Decode(fileContent)
		fileCertificate, err := x509.ParseCertificate(pemBlock.Bytes)
		if err == nil {
			trustedCertificatesNames = append(trustedCertificatesNames, fileCertificate.Subject.CommonName)
		}
		if !loadCertificateSucess {
			fmt.Println("Erro ao carregar certificado Root:", file.Name())
			continue
		}
	}
	// fmt.Println(*trustedCertificates)
	verifyCertificationOption = &x509.VerifyOptions{
		Roots: trustedCertificates,
	}
	verifyCertificationOption.KeyUsages = append(verifyCertificationOption.KeyUsages, x509.ExtKeyUsageClientAuth)

}

func main() {

	serverHTTPS := &http.Server{
		Addr: "0.0.0.0:4443",
		TLSConfig: &tls.Config{
			ClientAuth: tls.RequestClientCert,
			MinVersion: tls.VersionTLS12,
			MaxVersion: tls.VersionTLS12,
		},
	}

	http.HandleFunc("/", Home)

	http.HandleFunc("/login", Login)

	serverHTTPS.SetKeepAlivesEnabled(false)

	err := serverHTTPS.ListenAndServeTLS("siteCerts/fullchain2.pem", "siteCerts/privkey2.pem")
	if err != nil {
		log.Panic(err)
	}
}
