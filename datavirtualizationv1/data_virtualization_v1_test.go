/**
 * (C) Copyright IBM Corp. 2021.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package datavirtualizationv1_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"time"

	"github.com/IBM/data-virtualization-on-cloud-go-sdk/datavirtualizationv1"
	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/go-openapi/strfmt"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe(`DataVirtualizationV1`, func() {
	var testServer *httptest.Server
	Describe(`Service constructor tests`, func() {
		It(`Instantiate service client`, func() {
			dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
				Authenticator: &core.NoAuthAuthenticator{},
			})
			Expect(dataVirtualizationService).ToNot(BeNil())
			Expect(serviceErr).To(BeNil())
		})
		It(`Instantiate service client with error: Invalid URL`, func() {
			dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
				URL: "{BAD_URL_STRING",
			})
			Expect(dataVirtualizationService).To(BeNil())
			Expect(serviceErr).ToNot(BeNil())
		})
		It(`Instantiate service client with error: Invalid Auth`, func() {
			dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
				URL: "https://datavirtualizationv1/api",
				Authenticator: &core.BasicAuthenticator{
					Username: "",
					Password: "",
				},
			})
			Expect(dataVirtualizationService).To(BeNil())
			Expect(serviceErr).ToNot(BeNil())
		})
	})
	Describe(`Service constructor tests using external config`, func() {
		Context(`Using external config, construct service client instances`, func() {
			// Map containing environment variables used in testing.
			var testEnvironment = map[string]string{
				"DATA_VIRTUALIZATION_URL": "https://datavirtualizationv1/api",
				"DATA_VIRTUALIZATION_AUTH_TYPE": "noauth",
			}

			It(`Create service client using external config successfully`, func() {
				SetTestEnvironment(testEnvironment)
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1UsingExternalConfig(&datavirtualizationv1.DataVirtualizationV1Options{
				})
				Expect(dataVirtualizationService).ToNot(BeNil())
				Expect(serviceErr).To(BeNil())
				ClearTestEnvironment(testEnvironment)

				clone := dataVirtualizationService.Clone()
				Expect(clone).ToNot(BeNil())
				Expect(clone.Service != dataVirtualizationService.Service).To(BeTrue())
				Expect(clone.GetServiceURL()).To(Equal(dataVirtualizationService.GetServiceURL()))
				Expect(clone.Service.Options.Authenticator).To(Equal(dataVirtualizationService.Service.Options.Authenticator))
			})
			It(`Create service client using external config and set url from constructor successfully`, func() {
				SetTestEnvironment(testEnvironment)
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1UsingExternalConfig(&datavirtualizationv1.DataVirtualizationV1Options{
					URL: "https://testService/api",
				})
				Expect(dataVirtualizationService).ToNot(BeNil())
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService.Service.GetServiceURL()).To(Equal("https://testService/api"))
				ClearTestEnvironment(testEnvironment)

				clone := dataVirtualizationService.Clone()
				Expect(clone).ToNot(BeNil())
				Expect(clone.Service != dataVirtualizationService.Service).To(BeTrue())
				Expect(clone.GetServiceURL()).To(Equal(dataVirtualizationService.GetServiceURL()))
				Expect(clone.Service.Options.Authenticator).To(Equal(dataVirtualizationService.Service.Options.Authenticator))
			})
			It(`Create service client using external config and set url programatically successfully`, func() {
				SetTestEnvironment(testEnvironment)
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1UsingExternalConfig(&datavirtualizationv1.DataVirtualizationV1Options{
				})
				err := dataVirtualizationService.SetServiceURL("https://testService/api")
				Expect(err).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService.Service.GetServiceURL()).To(Equal("https://testService/api"))
				ClearTestEnvironment(testEnvironment)

				clone := dataVirtualizationService.Clone()
				Expect(clone).ToNot(BeNil())
				Expect(clone.Service != dataVirtualizationService.Service).To(BeTrue())
				Expect(clone.GetServiceURL()).To(Equal(dataVirtualizationService.GetServiceURL()))
				Expect(clone.Service.Options.Authenticator).To(Equal(dataVirtualizationService.Service.Options.Authenticator))
			})
		})
		Context(`Using external config, construct service client instances with error: Invalid Auth`, func() {
			// Map containing environment variables used in testing.
			var testEnvironment = map[string]string{
				"DATA_VIRTUALIZATION_URL": "https://datavirtualizationv1/api",
				"DATA_VIRTUALIZATION_AUTH_TYPE": "someOtherAuth",
			}

			SetTestEnvironment(testEnvironment)
			dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1UsingExternalConfig(&datavirtualizationv1.DataVirtualizationV1Options{
			})

			It(`Instantiate service client with error`, func() {
				Expect(dataVirtualizationService).To(BeNil())
				Expect(serviceErr).ToNot(BeNil())
				ClearTestEnvironment(testEnvironment)
			})
		})
		Context(`Using external config, construct service client instances with error: Invalid URL`, func() {
			// Map containing environment variables used in testing.
			var testEnvironment = map[string]string{
				"DATA_VIRTUALIZATION_AUTH_TYPE":   "NOAuth",
			}

			SetTestEnvironment(testEnvironment)
			dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1UsingExternalConfig(&datavirtualizationv1.DataVirtualizationV1Options{
				URL: "{BAD_URL_STRING",
			})

			It(`Instantiate service client with error`, func() {
				Expect(dataVirtualizationService).To(BeNil())
				Expect(serviceErr).ToNot(BeNil())
				ClearTestEnvironment(testEnvironment)
			})
		})
	})
	Describe(`Regional endpoint tests`, func() {
		It(`GetServiceURLForRegion(region string)`, func() {
			var url string
			var err error
			url, err = datavirtualizationv1.GetServiceURLForRegion("INVALID_REGION")
			Expect(url).To(BeEmpty())
			Expect(err).ToNot(BeNil())
			fmt.Fprintf(GinkgoWriter, "Expected error: %s\n", err.Error())
		})
	})
	Describe(`ListDatasourceConnections(listDatasourceConnectionsOptions *ListDatasourceConnectionsOptions) - Operation response error`, func() {
		listDatasourceConnectionsPath := "/v2/datasource/connections"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(listDatasourceConnectionsPath))
					Expect(req.Method).To(Equal("GET"))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke ListDatasourceConnections with error: Operation response processing error`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())

				// Construct an instance of the ListDatasourceConnectionsOptions model
				listDatasourceConnectionsOptionsModel := new(datavirtualizationv1.ListDatasourceConnectionsOptions)
				listDatasourceConnectionsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := dataVirtualizationService.ListDatasourceConnections(listDatasourceConnectionsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				dataVirtualizationService.EnableRetries(0, 0)
				result, response, operationErr = dataVirtualizationService.ListDatasourceConnections(listDatasourceConnectionsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`ListDatasourceConnections(listDatasourceConnectionsOptions *ListDatasourceConnectionsOptions)`, func() {
		listDatasourceConnectionsPath := "/v2/datasource/connections"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(listDatasourceConnectionsPath))
					Expect(req.Method).To(Equal("GET"))

					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"datasource_connections": [{"node_name": "NodeName", "node_description": "NodeDescription", "agent_class": "AgentClass", "hostname": "Hostname", "port": "Port", "os_user": "OsUser", "is_docker": "IsDocker", "dscount": "Dscount", "data_sources": [{"cid": "Cid", "dbname": "Dbname", "connection_id": "ConnectionID", "srchostname": "Srchostname", "srcport": "Srcport", "srctype": "Srctype", "usr": "Usr", "uri": "URI", "status": "Status", "connection_name": "ConnectionName"}]}]}`)
				}))
			})
			It(`Invoke ListDatasourceConnections successfully with retries`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())
				dataVirtualizationService.EnableRetries(0, 0)

				// Construct an instance of the ListDatasourceConnectionsOptions model
				listDatasourceConnectionsOptionsModel := new(datavirtualizationv1.ListDatasourceConnectionsOptions)
				listDatasourceConnectionsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := dataVirtualizationService.ListDatasourceConnectionsWithContext(ctx, listDatasourceConnectionsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				dataVirtualizationService.DisableRetries()
				result, response, operationErr := dataVirtualizationService.ListDatasourceConnections(listDatasourceConnectionsOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = dataVirtualizationService.ListDatasourceConnectionsWithContext(ctx, listDatasourceConnectionsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(listDatasourceConnectionsPath))
					Expect(req.Method).To(Equal("GET"))

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"datasource_connections": [{"node_name": "NodeName", "node_description": "NodeDescription", "agent_class": "AgentClass", "hostname": "Hostname", "port": "Port", "os_user": "OsUser", "is_docker": "IsDocker", "dscount": "Dscount", "data_sources": [{"cid": "Cid", "dbname": "Dbname", "connection_id": "ConnectionID", "srchostname": "Srchostname", "srcport": "Srcport", "srctype": "Srctype", "usr": "Usr", "uri": "URI", "status": "Status", "connection_name": "ConnectionName"}]}]}`)
				}))
			})
			It(`Invoke ListDatasourceConnections successfully`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := dataVirtualizationService.ListDatasourceConnections(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the ListDatasourceConnectionsOptions model
				listDatasourceConnectionsOptionsModel := new(datavirtualizationv1.ListDatasourceConnectionsOptions)
				listDatasourceConnectionsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = dataVirtualizationService.ListDatasourceConnections(listDatasourceConnectionsOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke ListDatasourceConnections with error: Operation request error`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())

				// Construct an instance of the ListDatasourceConnectionsOptions model
				listDatasourceConnectionsOptionsModel := new(datavirtualizationv1.ListDatasourceConnectionsOptions)
				listDatasourceConnectionsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := dataVirtualizationService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := dataVirtualizationService.ListDatasourceConnections(listDatasourceConnectionsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(200)
				}))
			})
			It(`Invoke ListDatasourceConnections successfully`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())

				// Construct an instance of the ListDatasourceConnectionsOptions model
				listDatasourceConnectionsOptionsModel := new(datavirtualizationv1.ListDatasourceConnectionsOptions)
				listDatasourceConnectionsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := dataVirtualizationService.ListDatasourceConnections(listDatasourceConnectionsOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`AddDatasourceConnection(addDatasourceConnectionOptions *AddDatasourceConnectionOptions) - Operation response error`, func() {
		addDatasourceConnectionPath := "/v2/datasource/connections"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(addDatasourceConnectionPath))
					Expect(req.Method).To(Equal("POST"))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(201)
					fmt.Fprintf(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke AddDatasourceConnection with error: Operation response processing error`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())

				// Construct an instance of the PostDatasourceConnectionParametersProperties model
				postDatasourceConnectionParametersPropertiesModel := new(datavirtualizationv1.PostDatasourceConnectionParametersProperties)
				postDatasourceConnectionParametersPropertiesModel.AccessToken = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.AccountName = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.APIKey = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.AuthType = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.ClientID = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.ClientSecret = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Collection = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Credentials = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Database = core.StringPtr("TPCDS")
				postDatasourceConnectionParametersPropertiesModel.Host = core.StringPtr("192.168.0.1")
				postDatasourceConnectionParametersPropertiesModel.HTTPPath = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.JarUris = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.JdbcDriver = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.JdbcURL = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Password = core.StringPtr("password")
				postDatasourceConnectionParametersPropertiesModel.Port = core.StringPtr("50000")
				postDatasourceConnectionParametersPropertiesModel.ProjectID = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Properties = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.RefreshToken = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Role = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.SapGatewayURL = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Server = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.ServiceName = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Sid = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Ssl = core.StringPtr("false")
				postDatasourceConnectionParametersPropertiesModel.SslCertificate = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.SslCertificateHost = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.SslCertificateValidation = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Username = core.StringPtr("db2inst1")
				postDatasourceConnectionParametersPropertiesModel.Warehouse = core.StringPtr("testString")

				// Construct an instance of the AddDatasourceConnectionOptions model
				addDatasourceConnectionOptionsModel := new(datavirtualizationv1.AddDatasourceConnectionOptions)
				addDatasourceConnectionOptionsModel.DatasourceType = core.StringPtr("DB2")
				addDatasourceConnectionOptionsModel.Name = core.StringPtr("DB2")
				addDatasourceConnectionOptionsModel.OriginCountry = core.StringPtr("us")
				addDatasourceConnectionOptionsModel.Properties = postDatasourceConnectionParametersPropertiesModel
				addDatasourceConnectionOptionsModel.AssetCategory = core.StringPtr("testString")
				addDatasourceConnectionOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := dataVirtualizationService.AddDatasourceConnection(addDatasourceConnectionOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				dataVirtualizationService.EnableRetries(0, 0)
				result, response, operationErr = dataVirtualizationService.AddDatasourceConnection(addDatasourceConnectionOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`AddDatasourceConnection(addDatasourceConnectionOptions *AddDatasourceConnectionOptions)`, func() {
		addDatasourceConnectionPath := "/v2/datasource/connections"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(addDatasourceConnectionPath))
					Expect(req.Method).To(Equal("POST"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(201)
					fmt.Fprintf(res, "%s", `{"connection_id": "ConnectionID", "datasource_type": "DatasourceType", "name": "Name"}`)
				}))
			})
			It(`Invoke AddDatasourceConnection successfully with retries`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())
				dataVirtualizationService.EnableRetries(0, 0)

				// Construct an instance of the PostDatasourceConnectionParametersProperties model
				postDatasourceConnectionParametersPropertiesModel := new(datavirtualizationv1.PostDatasourceConnectionParametersProperties)
				postDatasourceConnectionParametersPropertiesModel.AccessToken = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.AccountName = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.APIKey = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.AuthType = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.ClientID = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.ClientSecret = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Collection = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Credentials = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Database = core.StringPtr("TPCDS")
				postDatasourceConnectionParametersPropertiesModel.Host = core.StringPtr("192.168.0.1")
				postDatasourceConnectionParametersPropertiesModel.HTTPPath = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.JarUris = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.JdbcDriver = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.JdbcURL = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Password = core.StringPtr("password")
				postDatasourceConnectionParametersPropertiesModel.Port = core.StringPtr("50000")
				postDatasourceConnectionParametersPropertiesModel.ProjectID = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Properties = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.RefreshToken = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Role = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.SapGatewayURL = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Server = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.ServiceName = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Sid = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Ssl = core.StringPtr("false")
				postDatasourceConnectionParametersPropertiesModel.SslCertificate = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.SslCertificateHost = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.SslCertificateValidation = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Username = core.StringPtr("db2inst1")
				postDatasourceConnectionParametersPropertiesModel.Warehouse = core.StringPtr("testString")

				// Construct an instance of the AddDatasourceConnectionOptions model
				addDatasourceConnectionOptionsModel := new(datavirtualizationv1.AddDatasourceConnectionOptions)
				addDatasourceConnectionOptionsModel.DatasourceType = core.StringPtr("DB2")
				addDatasourceConnectionOptionsModel.Name = core.StringPtr("DB2")
				addDatasourceConnectionOptionsModel.OriginCountry = core.StringPtr("us")
				addDatasourceConnectionOptionsModel.Properties = postDatasourceConnectionParametersPropertiesModel
				addDatasourceConnectionOptionsModel.AssetCategory = core.StringPtr("testString")
				addDatasourceConnectionOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := dataVirtualizationService.AddDatasourceConnectionWithContext(ctx, addDatasourceConnectionOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				dataVirtualizationService.DisableRetries()
				result, response, operationErr := dataVirtualizationService.AddDatasourceConnection(addDatasourceConnectionOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = dataVirtualizationService.AddDatasourceConnectionWithContext(ctx, addDatasourceConnectionOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(addDatasourceConnectionPath))
					Expect(req.Method).To(Equal("POST"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(201)
					fmt.Fprintf(res, "%s", `{"connection_id": "ConnectionID", "datasource_type": "DatasourceType", "name": "Name"}`)
				}))
			})
			It(`Invoke AddDatasourceConnection successfully`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := dataVirtualizationService.AddDatasourceConnection(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the PostDatasourceConnectionParametersProperties model
				postDatasourceConnectionParametersPropertiesModel := new(datavirtualizationv1.PostDatasourceConnectionParametersProperties)
				postDatasourceConnectionParametersPropertiesModel.AccessToken = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.AccountName = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.APIKey = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.AuthType = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.ClientID = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.ClientSecret = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Collection = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Credentials = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Database = core.StringPtr("TPCDS")
				postDatasourceConnectionParametersPropertiesModel.Host = core.StringPtr("192.168.0.1")
				postDatasourceConnectionParametersPropertiesModel.HTTPPath = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.JarUris = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.JdbcDriver = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.JdbcURL = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Password = core.StringPtr("password")
				postDatasourceConnectionParametersPropertiesModel.Port = core.StringPtr("50000")
				postDatasourceConnectionParametersPropertiesModel.ProjectID = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Properties = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.RefreshToken = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Role = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.SapGatewayURL = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Server = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.ServiceName = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Sid = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Ssl = core.StringPtr("false")
				postDatasourceConnectionParametersPropertiesModel.SslCertificate = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.SslCertificateHost = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.SslCertificateValidation = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Username = core.StringPtr("db2inst1")
				postDatasourceConnectionParametersPropertiesModel.Warehouse = core.StringPtr("testString")

				// Construct an instance of the AddDatasourceConnectionOptions model
				addDatasourceConnectionOptionsModel := new(datavirtualizationv1.AddDatasourceConnectionOptions)
				addDatasourceConnectionOptionsModel.DatasourceType = core.StringPtr("DB2")
				addDatasourceConnectionOptionsModel.Name = core.StringPtr("DB2")
				addDatasourceConnectionOptionsModel.OriginCountry = core.StringPtr("us")
				addDatasourceConnectionOptionsModel.Properties = postDatasourceConnectionParametersPropertiesModel
				addDatasourceConnectionOptionsModel.AssetCategory = core.StringPtr("testString")
				addDatasourceConnectionOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = dataVirtualizationService.AddDatasourceConnection(addDatasourceConnectionOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke AddDatasourceConnection with error: Operation validation and request error`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())

				// Construct an instance of the PostDatasourceConnectionParametersProperties model
				postDatasourceConnectionParametersPropertiesModel := new(datavirtualizationv1.PostDatasourceConnectionParametersProperties)
				postDatasourceConnectionParametersPropertiesModel.AccessToken = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.AccountName = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.APIKey = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.AuthType = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.ClientID = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.ClientSecret = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Collection = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Credentials = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Database = core.StringPtr("TPCDS")
				postDatasourceConnectionParametersPropertiesModel.Host = core.StringPtr("192.168.0.1")
				postDatasourceConnectionParametersPropertiesModel.HTTPPath = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.JarUris = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.JdbcDriver = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.JdbcURL = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Password = core.StringPtr("password")
				postDatasourceConnectionParametersPropertiesModel.Port = core.StringPtr("50000")
				postDatasourceConnectionParametersPropertiesModel.ProjectID = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Properties = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.RefreshToken = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Role = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.SapGatewayURL = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Server = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.ServiceName = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Sid = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Ssl = core.StringPtr("false")
				postDatasourceConnectionParametersPropertiesModel.SslCertificate = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.SslCertificateHost = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.SslCertificateValidation = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Username = core.StringPtr("db2inst1")
				postDatasourceConnectionParametersPropertiesModel.Warehouse = core.StringPtr("testString")

				// Construct an instance of the AddDatasourceConnectionOptions model
				addDatasourceConnectionOptionsModel := new(datavirtualizationv1.AddDatasourceConnectionOptions)
				addDatasourceConnectionOptionsModel.DatasourceType = core.StringPtr("DB2")
				addDatasourceConnectionOptionsModel.Name = core.StringPtr("DB2")
				addDatasourceConnectionOptionsModel.OriginCountry = core.StringPtr("us")
				addDatasourceConnectionOptionsModel.Properties = postDatasourceConnectionParametersPropertiesModel
				addDatasourceConnectionOptionsModel.AssetCategory = core.StringPtr("testString")
				addDatasourceConnectionOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := dataVirtualizationService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := dataVirtualizationService.AddDatasourceConnection(addDatasourceConnectionOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the AddDatasourceConnectionOptions model with no property values
				addDatasourceConnectionOptionsModelNew := new(datavirtualizationv1.AddDatasourceConnectionOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = dataVirtualizationService.AddDatasourceConnection(addDatasourceConnectionOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(201)
				}))
			})
			It(`Invoke AddDatasourceConnection successfully`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())

				// Construct an instance of the PostDatasourceConnectionParametersProperties model
				postDatasourceConnectionParametersPropertiesModel := new(datavirtualizationv1.PostDatasourceConnectionParametersProperties)
				postDatasourceConnectionParametersPropertiesModel.AccessToken = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.AccountName = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.APIKey = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.AuthType = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.ClientID = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.ClientSecret = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Collection = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Credentials = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Database = core.StringPtr("TPCDS")
				postDatasourceConnectionParametersPropertiesModel.Host = core.StringPtr("192.168.0.1")
				postDatasourceConnectionParametersPropertiesModel.HTTPPath = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.JarUris = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.JdbcDriver = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.JdbcURL = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Password = core.StringPtr("password")
				postDatasourceConnectionParametersPropertiesModel.Port = core.StringPtr("50000")
				postDatasourceConnectionParametersPropertiesModel.ProjectID = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Properties = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.RefreshToken = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Role = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.SapGatewayURL = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Server = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.ServiceName = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Sid = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Ssl = core.StringPtr("false")
				postDatasourceConnectionParametersPropertiesModel.SslCertificate = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.SslCertificateHost = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.SslCertificateValidation = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Username = core.StringPtr("db2inst1")
				postDatasourceConnectionParametersPropertiesModel.Warehouse = core.StringPtr("testString")

				// Construct an instance of the AddDatasourceConnectionOptions model
				addDatasourceConnectionOptionsModel := new(datavirtualizationv1.AddDatasourceConnectionOptions)
				addDatasourceConnectionOptionsModel.DatasourceType = core.StringPtr("DB2")
				addDatasourceConnectionOptionsModel.Name = core.StringPtr("DB2")
				addDatasourceConnectionOptionsModel.OriginCountry = core.StringPtr("us")
				addDatasourceConnectionOptionsModel.Properties = postDatasourceConnectionParametersPropertiesModel
				addDatasourceConnectionOptionsModel.AssetCategory = core.StringPtr("testString")
				addDatasourceConnectionOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := dataVirtualizationService.AddDatasourceConnection(addDatasourceConnectionOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`DeleteDatasourceConnection(deleteDatasourceConnectionOptions *DeleteDatasourceConnectionOptions)`, func() {
		deleteDatasourceConnectionPath := "/v2/datasource/connections/75e4d01b-7417-4abc-b267-8ffb393fb970"
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(deleteDatasourceConnectionPath))
					Expect(req.Method).To(Equal("DELETE"))

					Expect(req.URL.Query()["cid"]).To(Equal([]string{"DB210013"}))
					res.WriteHeader(204)
				}))
			})
			It(`Invoke DeleteDatasourceConnection successfully`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				response, operationErr := dataVirtualizationService.DeleteDatasourceConnection(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())

				// Construct an instance of the DeleteDatasourceConnectionOptions model
				deleteDatasourceConnectionOptionsModel := new(datavirtualizationv1.DeleteDatasourceConnectionOptions)
				deleteDatasourceConnectionOptionsModel.ConnectionID = core.StringPtr("75e4d01b-7417-4abc-b267-8ffb393fb970")
				deleteDatasourceConnectionOptionsModel.Cid = core.StringPtr("DB210013")
				deleteDatasourceConnectionOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				response, operationErr = dataVirtualizationService.DeleteDatasourceConnection(deleteDatasourceConnectionOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
			})
			It(`Invoke DeleteDatasourceConnection with error: Operation validation and request error`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())

				// Construct an instance of the DeleteDatasourceConnectionOptions model
				deleteDatasourceConnectionOptionsModel := new(datavirtualizationv1.DeleteDatasourceConnectionOptions)
				deleteDatasourceConnectionOptionsModel.ConnectionID = core.StringPtr("75e4d01b-7417-4abc-b267-8ffb393fb970")
				deleteDatasourceConnectionOptionsModel.Cid = core.StringPtr("DB210013")
				deleteDatasourceConnectionOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := dataVirtualizationService.SetServiceURL("")
				Expect(err).To(BeNil())
				response, operationErr := dataVirtualizationService.DeleteDatasourceConnection(deleteDatasourceConnectionOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				// Construct a second instance of the DeleteDatasourceConnectionOptions model with no property values
				deleteDatasourceConnectionOptionsModelNew := new(datavirtualizationv1.DeleteDatasourceConnectionOptions)
				// Invoke operation with invalid model (negative test)
				response, operationErr = dataVirtualizationService.DeleteDatasourceConnection(deleteDatasourceConnectionOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GrantUserToVirtualTable(grantUserToVirtualTableOptions *GrantUserToVirtualTableOptions)`, func() {
		grantUserToVirtualTablePath := "/v2/privileges/users"
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(grantUserToVirtualTablePath))
					Expect(req.Method).To(Equal("POST"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					res.WriteHeader(204)
				}))
			})
			It(`Invoke GrantUserToVirtualTable successfully`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				response, operationErr := dataVirtualizationService.GrantUserToVirtualTable(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())

				// Construct an instance of the GrantUserToVirtualTableOptions model
				grantUserToVirtualTableOptionsModel := new(datavirtualizationv1.GrantUserToVirtualTableOptions)
				grantUserToVirtualTableOptionsModel.TableName = core.StringPtr("EMPLOYEE")
				grantUserToVirtualTableOptionsModel.TableSchema = core.StringPtr("dv_ibmid_060000s4y5")
				grantUserToVirtualTableOptionsModel.Authid = core.StringPtr("PUBLIC")
				grantUserToVirtualTableOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				response, operationErr = dataVirtualizationService.GrantUserToVirtualTable(grantUserToVirtualTableOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
			})
			It(`Invoke GrantUserToVirtualTable with error: Operation validation and request error`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())

				// Construct an instance of the GrantUserToVirtualTableOptions model
				grantUserToVirtualTableOptionsModel := new(datavirtualizationv1.GrantUserToVirtualTableOptions)
				grantUserToVirtualTableOptionsModel.TableName = core.StringPtr("EMPLOYEE")
				grantUserToVirtualTableOptionsModel.TableSchema = core.StringPtr("dv_ibmid_060000s4y5")
				grantUserToVirtualTableOptionsModel.Authid = core.StringPtr("PUBLIC")
				grantUserToVirtualTableOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := dataVirtualizationService.SetServiceURL("")
				Expect(err).To(BeNil())
				response, operationErr := dataVirtualizationService.GrantUserToVirtualTable(grantUserToVirtualTableOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				// Construct a second instance of the GrantUserToVirtualTableOptions model with no property values
				grantUserToVirtualTableOptionsModelNew := new(datavirtualizationv1.GrantUserToVirtualTableOptions)
				// Invoke operation with invalid model (negative test)
				response, operationErr = dataVirtualizationService.GrantUserToVirtualTable(grantUserToVirtualTableOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`RevokeUserFromObject(revokeUserFromObjectOptions *RevokeUserFromObjectOptions)`, func() {
		revokeUserFromObjectPath := "/v2/privileges/users/PUBLIC"
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(revokeUserFromObjectPath))
					Expect(req.Method).To(Equal("DELETE"))

					Expect(req.URL.Query()["table_name"]).To(Equal([]string{"EMPLOYEE"}))
					Expect(req.URL.Query()["table_schema"]).To(Equal([]string{"dv_ibmid_060000s4y5"}))
					res.WriteHeader(204)
				}))
			})
			It(`Invoke RevokeUserFromObject successfully`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				response, operationErr := dataVirtualizationService.RevokeUserFromObject(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())

				// Construct an instance of the RevokeUserFromObjectOptions model
				revokeUserFromObjectOptionsModel := new(datavirtualizationv1.RevokeUserFromObjectOptions)
				revokeUserFromObjectOptionsModel.Authid = core.StringPtr("PUBLIC")
				revokeUserFromObjectOptionsModel.TableName = core.StringPtr("EMPLOYEE")
				revokeUserFromObjectOptionsModel.TableSchema = core.StringPtr("dv_ibmid_060000s4y5")
				revokeUserFromObjectOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				response, operationErr = dataVirtualizationService.RevokeUserFromObject(revokeUserFromObjectOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
			})
			It(`Invoke RevokeUserFromObject with error: Operation validation and request error`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())

				// Construct an instance of the RevokeUserFromObjectOptions model
				revokeUserFromObjectOptionsModel := new(datavirtualizationv1.RevokeUserFromObjectOptions)
				revokeUserFromObjectOptionsModel.Authid = core.StringPtr("PUBLIC")
				revokeUserFromObjectOptionsModel.TableName = core.StringPtr("EMPLOYEE")
				revokeUserFromObjectOptionsModel.TableSchema = core.StringPtr("dv_ibmid_060000s4y5")
				revokeUserFromObjectOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := dataVirtualizationService.SetServiceURL("")
				Expect(err).To(BeNil())
				response, operationErr := dataVirtualizationService.RevokeUserFromObject(revokeUserFromObjectOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				// Construct a second instance of the RevokeUserFromObjectOptions model with no property values
				revokeUserFromObjectOptionsModelNew := new(datavirtualizationv1.RevokeUserFromObjectOptions)
				// Invoke operation with invalid model (negative test)
				response, operationErr = dataVirtualizationService.RevokeUserFromObject(revokeUserFromObjectOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GrantRolesToVirtualizedTable(grantRolesToVirtualizedTableOptions *GrantRolesToVirtualizedTableOptions)`, func() {
		grantRolesToVirtualizedTablePath := "/v2/privileges/roles"
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(grantRolesToVirtualizedTablePath))
					Expect(req.Method).To(Equal("POST"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					res.WriteHeader(204)
				}))
			})
			It(`Invoke GrantRolesToVirtualizedTable successfully`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				response, operationErr := dataVirtualizationService.GrantRolesToVirtualizedTable(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())

				// Construct an instance of the GrantRolesToVirtualizedTableOptions model
				grantRolesToVirtualizedTableOptionsModel := new(datavirtualizationv1.GrantRolesToVirtualizedTableOptions)
				grantRolesToVirtualizedTableOptionsModel.TableName = core.StringPtr("EMPLOYEE")
				grantRolesToVirtualizedTableOptionsModel.TableSchema = core.StringPtr("dv_ibmid_060000s4y5")
				grantRolesToVirtualizedTableOptionsModel.RoleName = core.StringPtr("PUBLIC")
				grantRolesToVirtualizedTableOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				response, operationErr = dataVirtualizationService.GrantRolesToVirtualizedTable(grantRolesToVirtualizedTableOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
			})
			It(`Invoke GrantRolesToVirtualizedTable with error: Operation validation and request error`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())

				// Construct an instance of the GrantRolesToVirtualizedTableOptions model
				grantRolesToVirtualizedTableOptionsModel := new(datavirtualizationv1.GrantRolesToVirtualizedTableOptions)
				grantRolesToVirtualizedTableOptionsModel.TableName = core.StringPtr("EMPLOYEE")
				grantRolesToVirtualizedTableOptionsModel.TableSchema = core.StringPtr("dv_ibmid_060000s4y5")
				grantRolesToVirtualizedTableOptionsModel.RoleName = core.StringPtr("PUBLIC")
				grantRolesToVirtualizedTableOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := dataVirtualizationService.SetServiceURL("")
				Expect(err).To(BeNil())
				response, operationErr := dataVirtualizationService.GrantRolesToVirtualizedTable(grantRolesToVirtualizedTableOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				// Construct a second instance of the GrantRolesToVirtualizedTableOptions model with no property values
				grantRolesToVirtualizedTableOptionsModelNew := new(datavirtualizationv1.GrantRolesToVirtualizedTableOptions)
				// Invoke operation with invalid model (negative test)
				response, operationErr = dataVirtualizationService.GrantRolesToVirtualizedTable(grantRolesToVirtualizedTableOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`DvaasRevokeRoleFromTable(dvaasRevokeRoleFromTableOptions *DvaasRevokeRoleFromTableOptions)`, func() {
		dvaasRevokeRoleFromTablePath := "/v2/privileges/roles/DV_ENGINEER"
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(dvaasRevokeRoleFromTablePath))
					Expect(req.Method).To(Equal("DELETE"))

					Expect(req.URL.Query()["table_name"]).To(Equal([]string{"EMPLOYEE"}))
					Expect(req.URL.Query()["table_schema"]).To(Equal([]string{"dv_ibmid_060000s4y5"}))
					res.WriteHeader(204)
				}))
			})
			It(`Invoke DvaasRevokeRoleFromTable successfully`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				response, operationErr := dataVirtualizationService.DvaasRevokeRoleFromTable(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())

				// Construct an instance of the DvaasRevokeRoleFromTableOptions model
				dvaasRevokeRoleFromTableOptionsModel := new(datavirtualizationv1.DvaasRevokeRoleFromTableOptions)
				dvaasRevokeRoleFromTableOptionsModel.RoleName = core.StringPtr("DV_ENGINEER")
				dvaasRevokeRoleFromTableOptionsModel.TableName = core.StringPtr("EMPLOYEE")
				dvaasRevokeRoleFromTableOptionsModel.TableSchema = core.StringPtr("dv_ibmid_060000s4y5")
				dvaasRevokeRoleFromTableOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				response, operationErr = dataVirtualizationService.DvaasRevokeRoleFromTable(dvaasRevokeRoleFromTableOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
			})
			It(`Invoke DvaasRevokeRoleFromTable with error: Operation validation and request error`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())

				// Construct an instance of the DvaasRevokeRoleFromTableOptions model
				dvaasRevokeRoleFromTableOptionsModel := new(datavirtualizationv1.DvaasRevokeRoleFromTableOptions)
				dvaasRevokeRoleFromTableOptionsModel.RoleName = core.StringPtr("DV_ENGINEER")
				dvaasRevokeRoleFromTableOptionsModel.TableName = core.StringPtr("EMPLOYEE")
				dvaasRevokeRoleFromTableOptionsModel.TableSchema = core.StringPtr("dv_ibmid_060000s4y5")
				dvaasRevokeRoleFromTableOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := dataVirtualizationService.SetServiceURL("")
				Expect(err).To(BeNil())
				response, operationErr := dataVirtualizationService.DvaasRevokeRoleFromTable(dvaasRevokeRoleFromTableOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				// Construct a second instance of the DvaasRevokeRoleFromTableOptions model with no property values
				dvaasRevokeRoleFromTableOptionsModelNew := new(datavirtualizationv1.DvaasRevokeRoleFromTableOptions)
				// Invoke operation with invalid model (negative test)
				response, operationErr = dataVirtualizationService.DvaasRevokeRoleFromTable(dvaasRevokeRoleFromTableOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`ListTablesForRole(listTablesForRoleOptions *ListTablesForRoleOptions) - Operation response error`, func() {
		listTablesForRolePath := "/v2/privileges/tables"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(listTablesForRolePath))
					Expect(req.Method).To(Equal("GET"))
					Expect(req.URL.Query()["rolename"]).To(Equal([]string{"MANAGER | STEWARD | ENGINEER | USER"}))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke ListTablesForRole with error: Operation response processing error`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())

				// Construct an instance of the ListTablesForRoleOptions model
				listTablesForRoleOptionsModel := new(datavirtualizationv1.ListTablesForRoleOptions)
				listTablesForRoleOptionsModel.Rolename = core.StringPtr("MANAGER | STEWARD | ENGINEER | USER")
				listTablesForRoleOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := dataVirtualizationService.ListTablesForRole(listTablesForRoleOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				dataVirtualizationService.EnableRetries(0, 0)
				result, response, operationErr = dataVirtualizationService.ListTablesForRole(listTablesForRoleOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`ListTablesForRole(listTablesForRoleOptions *ListTablesForRoleOptions)`, func() {
		listTablesForRolePath := "/v2/privileges/tables"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(listTablesForRolePath))
					Expect(req.Method).To(Equal("GET"))

					Expect(req.URL.Query()["rolename"]).To(Equal([]string{"MANAGER | STEWARD | ENGINEER | USER"}))
					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"objects": [{"table_name": "TableName", "table_schema": "TableSchema"}]}`)
				}))
			})
			It(`Invoke ListTablesForRole successfully with retries`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())
				dataVirtualizationService.EnableRetries(0, 0)

				// Construct an instance of the ListTablesForRoleOptions model
				listTablesForRoleOptionsModel := new(datavirtualizationv1.ListTablesForRoleOptions)
				listTablesForRoleOptionsModel.Rolename = core.StringPtr("MANAGER | STEWARD | ENGINEER | USER")
				listTablesForRoleOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := dataVirtualizationService.ListTablesForRoleWithContext(ctx, listTablesForRoleOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				dataVirtualizationService.DisableRetries()
				result, response, operationErr := dataVirtualizationService.ListTablesForRole(listTablesForRoleOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = dataVirtualizationService.ListTablesForRoleWithContext(ctx, listTablesForRoleOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(listTablesForRolePath))
					Expect(req.Method).To(Equal("GET"))

					Expect(req.URL.Query()["rolename"]).To(Equal([]string{"MANAGER | STEWARD | ENGINEER | USER"}))
					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"objects": [{"table_name": "TableName", "table_schema": "TableSchema"}]}`)
				}))
			})
			It(`Invoke ListTablesForRole successfully`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := dataVirtualizationService.ListTablesForRole(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the ListTablesForRoleOptions model
				listTablesForRoleOptionsModel := new(datavirtualizationv1.ListTablesForRoleOptions)
				listTablesForRoleOptionsModel.Rolename = core.StringPtr("MANAGER | STEWARD | ENGINEER | USER")
				listTablesForRoleOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = dataVirtualizationService.ListTablesForRole(listTablesForRoleOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke ListTablesForRole with error: Operation validation and request error`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())

				// Construct an instance of the ListTablesForRoleOptions model
				listTablesForRoleOptionsModel := new(datavirtualizationv1.ListTablesForRoleOptions)
				listTablesForRoleOptionsModel.Rolename = core.StringPtr("MANAGER | STEWARD | ENGINEER | USER")
				listTablesForRoleOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := dataVirtualizationService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := dataVirtualizationService.ListTablesForRole(listTablesForRoleOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the ListTablesForRoleOptions model with no property values
				listTablesForRoleOptionsModelNew := new(datavirtualizationv1.ListTablesForRoleOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = dataVirtualizationService.ListTablesForRole(listTablesForRoleOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(200)
				}))
			})
			It(`Invoke ListTablesForRole successfully`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())

				// Construct an instance of the ListTablesForRoleOptions model
				listTablesForRoleOptionsModel := new(datavirtualizationv1.ListTablesForRoleOptions)
				listTablesForRoleOptionsModel.Rolename = core.StringPtr("MANAGER | STEWARD | ENGINEER | USER")
				listTablesForRoleOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := dataVirtualizationService.ListTablesForRole(listTablesForRoleOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`TurnOnPolicyV2(turnOnPolicyV2Options *TurnOnPolicyV2Options) - Operation response error`, func() {
		turnOnPolicyV2Path := "/v2/security/policy/status"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(turnOnPolicyV2Path))
					Expect(req.Method).To(Equal("PUT"))
					Expect(req.URL.Query()["status"]).To(Equal([]string{"enabled"}))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke TurnOnPolicyV2 with error: Operation response processing error`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())

				// Construct an instance of the TurnOnPolicyV2Options model
				turnOnPolicyV2OptionsModel := new(datavirtualizationv1.TurnOnPolicyV2Options)
				turnOnPolicyV2OptionsModel.Status = core.StringPtr("enabled")
				turnOnPolicyV2OptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := dataVirtualizationService.TurnOnPolicyV2(turnOnPolicyV2OptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				dataVirtualizationService.EnableRetries(0, 0)
				result, response, operationErr = dataVirtualizationService.TurnOnPolicyV2(turnOnPolicyV2OptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`TurnOnPolicyV2(turnOnPolicyV2Options *TurnOnPolicyV2Options)`, func() {
		turnOnPolicyV2Path := "/v2/security/policy/status"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(turnOnPolicyV2Path))
					Expect(req.Method).To(Equal("PUT"))

					Expect(req.URL.Query()["status"]).To(Equal([]string{"enabled"}))
					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"status": "enabled"}`)
				}))
			})
			It(`Invoke TurnOnPolicyV2 successfully with retries`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())
				dataVirtualizationService.EnableRetries(0, 0)

				// Construct an instance of the TurnOnPolicyV2Options model
				turnOnPolicyV2OptionsModel := new(datavirtualizationv1.TurnOnPolicyV2Options)
				turnOnPolicyV2OptionsModel.Status = core.StringPtr("enabled")
				turnOnPolicyV2OptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := dataVirtualizationService.TurnOnPolicyV2WithContext(ctx, turnOnPolicyV2OptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				dataVirtualizationService.DisableRetries()
				result, response, operationErr := dataVirtualizationService.TurnOnPolicyV2(turnOnPolicyV2OptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = dataVirtualizationService.TurnOnPolicyV2WithContext(ctx, turnOnPolicyV2OptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(turnOnPolicyV2Path))
					Expect(req.Method).To(Equal("PUT"))

					Expect(req.URL.Query()["status"]).To(Equal([]string{"enabled"}))
					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"status": "enabled"}`)
				}))
			})
			It(`Invoke TurnOnPolicyV2 successfully`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := dataVirtualizationService.TurnOnPolicyV2(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the TurnOnPolicyV2Options model
				turnOnPolicyV2OptionsModel := new(datavirtualizationv1.TurnOnPolicyV2Options)
				turnOnPolicyV2OptionsModel.Status = core.StringPtr("enabled")
				turnOnPolicyV2OptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = dataVirtualizationService.TurnOnPolicyV2(turnOnPolicyV2OptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke TurnOnPolicyV2 with error: Operation validation and request error`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())

				// Construct an instance of the TurnOnPolicyV2Options model
				turnOnPolicyV2OptionsModel := new(datavirtualizationv1.TurnOnPolicyV2Options)
				turnOnPolicyV2OptionsModel.Status = core.StringPtr("enabled")
				turnOnPolicyV2OptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := dataVirtualizationService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := dataVirtualizationService.TurnOnPolicyV2(turnOnPolicyV2OptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the TurnOnPolicyV2Options model with no property values
				turnOnPolicyV2OptionsModelNew := new(datavirtualizationv1.TurnOnPolicyV2Options)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = dataVirtualizationService.TurnOnPolicyV2(turnOnPolicyV2OptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(200)
				}))
			})
			It(`Invoke TurnOnPolicyV2 successfully`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())

				// Construct an instance of the TurnOnPolicyV2Options model
				turnOnPolicyV2OptionsModel := new(datavirtualizationv1.TurnOnPolicyV2Options)
				turnOnPolicyV2OptionsModel.Status = core.StringPtr("enabled")
				turnOnPolicyV2OptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := dataVirtualizationService.TurnOnPolicyV2(turnOnPolicyV2OptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`CheckPolicyStatusV2(checkPolicyStatusV2Options *CheckPolicyStatusV2Options) - Operation response error`, func() {
		checkPolicyStatusV2Path := "/v2/security/policy/status"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(checkPolicyStatusV2Path))
					Expect(req.Method).To(Equal("GET"))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke CheckPolicyStatusV2 with error: Operation response processing error`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())

				// Construct an instance of the CheckPolicyStatusV2Options model
				checkPolicyStatusV2OptionsModel := new(datavirtualizationv1.CheckPolicyStatusV2Options)
				checkPolicyStatusV2OptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := dataVirtualizationService.CheckPolicyStatusV2(checkPolicyStatusV2OptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				dataVirtualizationService.EnableRetries(0, 0)
				result, response, operationErr = dataVirtualizationService.CheckPolicyStatusV2(checkPolicyStatusV2OptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`CheckPolicyStatusV2(checkPolicyStatusV2Options *CheckPolicyStatusV2Options)`, func() {
		checkPolicyStatusV2Path := "/v2/security/policy/status"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(checkPolicyStatusV2Path))
					Expect(req.Method).To(Equal("GET"))

					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"status": "enabled"}`)
				}))
			})
			It(`Invoke CheckPolicyStatusV2 successfully with retries`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())
				dataVirtualizationService.EnableRetries(0, 0)

				// Construct an instance of the CheckPolicyStatusV2Options model
				checkPolicyStatusV2OptionsModel := new(datavirtualizationv1.CheckPolicyStatusV2Options)
				checkPolicyStatusV2OptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := dataVirtualizationService.CheckPolicyStatusV2WithContext(ctx, checkPolicyStatusV2OptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				dataVirtualizationService.DisableRetries()
				result, response, operationErr := dataVirtualizationService.CheckPolicyStatusV2(checkPolicyStatusV2OptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = dataVirtualizationService.CheckPolicyStatusV2WithContext(ctx, checkPolicyStatusV2OptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(checkPolicyStatusV2Path))
					Expect(req.Method).To(Equal("GET"))

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"status": "enabled"}`)
				}))
			})
			It(`Invoke CheckPolicyStatusV2 successfully`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := dataVirtualizationService.CheckPolicyStatusV2(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the CheckPolicyStatusV2Options model
				checkPolicyStatusV2OptionsModel := new(datavirtualizationv1.CheckPolicyStatusV2Options)
				checkPolicyStatusV2OptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = dataVirtualizationService.CheckPolicyStatusV2(checkPolicyStatusV2OptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke CheckPolicyStatusV2 with error: Operation request error`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())

				// Construct an instance of the CheckPolicyStatusV2Options model
				checkPolicyStatusV2OptionsModel := new(datavirtualizationv1.CheckPolicyStatusV2Options)
				checkPolicyStatusV2OptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := dataVirtualizationService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := dataVirtualizationService.CheckPolicyStatusV2(checkPolicyStatusV2OptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(200)
				}))
			})
			It(`Invoke CheckPolicyStatusV2 successfully`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())

				// Construct an instance of the CheckPolicyStatusV2Options model
				checkPolicyStatusV2OptionsModel := new(datavirtualizationv1.CheckPolicyStatusV2Options)
				checkPolicyStatusV2OptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := dataVirtualizationService.CheckPolicyStatusV2(checkPolicyStatusV2OptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`DvaasVirtualizeTable(dvaasVirtualizeTableOptions *DvaasVirtualizeTableOptions) - Operation response error`, func() {
		dvaasVirtualizeTablePath := "/v2/virtualization/tables"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(dvaasVirtualizeTablePath))
					Expect(req.Method).To(Equal("POST"))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(201)
					fmt.Fprintf(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke DvaasVirtualizeTable with error: Operation response processing error`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())

				// Construct an instance of the VirtualizeTableParameterSourceTableDefItem model
				virtualizeTableParameterSourceTableDefItemModel := new(datavirtualizationv1.VirtualizeTableParameterSourceTableDefItem)
				virtualizeTableParameterSourceTableDefItemModel.ColumnName = core.StringPtr("Column1")
				virtualizeTableParameterSourceTableDefItemModel.ColumnType = core.StringPtr("INTEGER")

				// Construct an instance of the VirtualizeTableParameterVirtualTableDefItem model
				virtualizeTableParameterVirtualTableDefItemModel := new(datavirtualizationv1.VirtualizeTableParameterVirtualTableDefItem)
				virtualizeTableParameterVirtualTableDefItemModel.ColumnName = core.StringPtr("Column_1")
				virtualizeTableParameterVirtualTableDefItemModel.ColumnType = core.StringPtr("INTEGER")

				// Construct an instance of the DvaasVirtualizeTableOptions model
				dvaasVirtualizeTableOptionsModel := new(datavirtualizationv1.DvaasVirtualizeTableOptions)
				dvaasVirtualizeTableOptionsModel.SourceName = core.StringPtr("Tab1")
				dvaasVirtualizeTableOptionsModel.SourceTableDef = []datavirtualizationv1.VirtualizeTableParameterSourceTableDefItem{*virtualizeTableParameterSourceTableDefItemModel}
				dvaasVirtualizeTableOptionsModel.Sources = []string{`DB210001:"Hjq1"`}
				dvaasVirtualizeTableOptionsModel.VirtualName = core.StringPtr("Tab1")
				dvaasVirtualizeTableOptionsModel.VirtualSchema = core.StringPtr("dv_ibmid_060000s4y5")
				dvaasVirtualizeTableOptionsModel.VirtualTableDef = []datavirtualizationv1.VirtualizeTableParameterVirtualTableDefItem{*virtualizeTableParameterVirtualTableDefItemModel}
				dvaasVirtualizeTableOptionsModel.IsIncludedColumns = core.StringPtr("Y, Y, N")
				dvaasVirtualizeTableOptionsModel.Replace = core.BoolPtr(false)
				dvaasVirtualizeTableOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := dataVirtualizationService.DvaasVirtualizeTable(dvaasVirtualizeTableOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				dataVirtualizationService.EnableRetries(0, 0)
				result, response, operationErr = dataVirtualizationService.DvaasVirtualizeTable(dvaasVirtualizeTableOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`DvaasVirtualizeTable(dvaasVirtualizeTableOptions *DvaasVirtualizeTableOptions)`, func() {
		dvaasVirtualizeTablePath := "/v2/virtualization/tables"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(dvaasVirtualizeTablePath))
					Expect(req.Method).To(Equal("POST"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(201)
					fmt.Fprintf(res, "%s", `{"table_name": "Tab1", "schema_name": "dv_ibmid_060000s4y5"}`)
				}))
			})
			It(`Invoke DvaasVirtualizeTable successfully with retries`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())
				dataVirtualizationService.EnableRetries(0, 0)

				// Construct an instance of the VirtualizeTableParameterSourceTableDefItem model
				virtualizeTableParameterSourceTableDefItemModel := new(datavirtualizationv1.VirtualizeTableParameterSourceTableDefItem)
				virtualizeTableParameterSourceTableDefItemModel.ColumnName = core.StringPtr("Column1")
				virtualizeTableParameterSourceTableDefItemModel.ColumnType = core.StringPtr("INTEGER")

				// Construct an instance of the VirtualizeTableParameterVirtualTableDefItem model
				virtualizeTableParameterVirtualTableDefItemModel := new(datavirtualizationv1.VirtualizeTableParameterVirtualTableDefItem)
				virtualizeTableParameterVirtualTableDefItemModel.ColumnName = core.StringPtr("Column_1")
				virtualizeTableParameterVirtualTableDefItemModel.ColumnType = core.StringPtr("INTEGER")

				// Construct an instance of the DvaasVirtualizeTableOptions model
				dvaasVirtualizeTableOptionsModel := new(datavirtualizationv1.DvaasVirtualizeTableOptions)
				dvaasVirtualizeTableOptionsModel.SourceName = core.StringPtr("Tab1")
				dvaasVirtualizeTableOptionsModel.SourceTableDef = []datavirtualizationv1.VirtualizeTableParameterSourceTableDefItem{*virtualizeTableParameterSourceTableDefItemModel}
				dvaasVirtualizeTableOptionsModel.Sources = []string{`DB210001:"Hjq1"`}
				dvaasVirtualizeTableOptionsModel.VirtualName = core.StringPtr("Tab1")
				dvaasVirtualizeTableOptionsModel.VirtualSchema = core.StringPtr("dv_ibmid_060000s4y5")
				dvaasVirtualizeTableOptionsModel.VirtualTableDef = []datavirtualizationv1.VirtualizeTableParameterVirtualTableDefItem{*virtualizeTableParameterVirtualTableDefItemModel}
				dvaasVirtualizeTableOptionsModel.IsIncludedColumns = core.StringPtr("Y, Y, N")
				dvaasVirtualizeTableOptionsModel.Replace = core.BoolPtr(false)
				dvaasVirtualizeTableOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := dataVirtualizationService.DvaasVirtualizeTableWithContext(ctx, dvaasVirtualizeTableOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				dataVirtualizationService.DisableRetries()
				result, response, operationErr := dataVirtualizationService.DvaasVirtualizeTable(dvaasVirtualizeTableOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = dataVirtualizationService.DvaasVirtualizeTableWithContext(ctx, dvaasVirtualizeTableOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(dvaasVirtualizeTablePath))
					Expect(req.Method).To(Equal("POST"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(201)
					fmt.Fprintf(res, "%s", `{"table_name": "Tab1", "schema_name": "dv_ibmid_060000s4y5"}`)
				}))
			})
			It(`Invoke DvaasVirtualizeTable successfully`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := dataVirtualizationService.DvaasVirtualizeTable(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the VirtualizeTableParameterSourceTableDefItem model
				virtualizeTableParameterSourceTableDefItemModel := new(datavirtualizationv1.VirtualizeTableParameterSourceTableDefItem)
				virtualizeTableParameterSourceTableDefItemModel.ColumnName = core.StringPtr("Column1")
				virtualizeTableParameterSourceTableDefItemModel.ColumnType = core.StringPtr("INTEGER")

				// Construct an instance of the VirtualizeTableParameterVirtualTableDefItem model
				virtualizeTableParameterVirtualTableDefItemModel := new(datavirtualizationv1.VirtualizeTableParameterVirtualTableDefItem)
				virtualizeTableParameterVirtualTableDefItemModel.ColumnName = core.StringPtr("Column_1")
				virtualizeTableParameterVirtualTableDefItemModel.ColumnType = core.StringPtr("INTEGER")

				// Construct an instance of the DvaasVirtualizeTableOptions model
				dvaasVirtualizeTableOptionsModel := new(datavirtualizationv1.DvaasVirtualizeTableOptions)
				dvaasVirtualizeTableOptionsModel.SourceName = core.StringPtr("Tab1")
				dvaasVirtualizeTableOptionsModel.SourceTableDef = []datavirtualizationv1.VirtualizeTableParameterSourceTableDefItem{*virtualizeTableParameterSourceTableDefItemModel}
				dvaasVirtualizeTableOptionsModel.Sources = []string{`DB210001:"Hjq1"`}
				dvaasVirtualizeTableOptionsModel.VirtualName = core.StringPtr("Tab1")
				dvaasVirtualizeTableOptionsModel.VirtualSchema = core.StringPtr("dv_ibmid_060000s4y5")
				dvaasVirtualizeTableOptionsModel.VirtualTableDef = []datavirtualizationv1.VirtualizeTableParameterVirtualTableDefItem{*virtualizeTableParameterVirtualTableDefItemModel}
				dvaasVirtualizeTableOptionsModel.IsIncludedColumns = core.StringPtr("Y, Y, N")
				dvaasVirtualizeTableOptionsModel.Replace = core.BoolPtr(false)
				dvaasVirtualizeTableOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = dataVirtualizationService.DvaasVirtualizeTable(dvaasVirtualizeTableOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke DvaasVirtualizeTable with error: Operation validation and request error`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())

				// Construct an instance of the VirtualizeTableParameterSourceTableDefItem model
				virtualizeTableParameterSourceTableDefItemModel := new(datavirtualizationv1.VirtualizeTableParameterSourceTableDefItem)
				virtualizeTableParameterSourceTableDefItemModel.ColumnName = core.StringPtr("Column1")
				virtualizeTableParameterSourceTableDefItemModel.ColumnType = core.StringPtr("INTEGER")

				// Construct an instance of the VirtualizeTableParameterVirtualTableDefItem model
				virtualizeTableParameterVirtualTableDefItemModel := new(datavirtualizationv1.VirtualizeTableParameterVirtualTableDefItem)
				virtualizeTableParameterVirtualTableDefItemModel.ColumnName = core.StringPtr("Column_1")
				virtualizeTableParameterVirtualTableDefItemModel.ColumnType = core.StringPtr("INTEGER")

				// Construct an instance of the DvaasVirtualizeTableOptions model
				dvaasVirtualizeTableOptionsModel := new(datavirtualizationv1.DvaasVirtualizeTableOptions)
				dvaasVirtualizeTableOptionsModel.SourceName = core.StringPtr("Tab1")
				dvaasVirtualizeTableOptionsModel.SourceTableDef = []datavirtualizationv1.VirtualizeTableParameterSourceTableDefItem{*virtualizeTableParameterSourceTableDefItemModel}
				dvaasVirtualizeTableOptionsModel.Sources = []string{`DB210001:"Hjq1"`}
				dvaasVirtualizeTableOptionsModel.VirtualName = core.StringPtr("Tab1")
				dvaasVirtualizeTableOptionsModel.VirtualSchema = core.StringPtr("dv_ibmid_060000s4y5")
				dvaasVirtualizeTableOptionsModel.VirtualTableDef = []datavirtualizationv1.VirtualizeTableParameterVirtualTableDefItem{*virtualizeTableParameterVirtualTableDefItemModel}
				dvaasVirtualizeTableOptionsModel.IsIncludedColumns = core.StringPtr("Y, Y, N")
				dvaasVirtualizeTableOptionsModel.Replace = core.BoolPtr(false)
				dvaasVirtualizeTableOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := dataVirtualizationService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := dataVirtualizationService.DvaasVirtualizeTable(dvaasVirtualizeTableOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the DvaasVirtualizeTableOptions model with no property values
				dvaasVirtualizeTableOptionsModelNew := new(datavirtualizationv1.DvaasVirtualizeTableOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = dataVirtualizationService.DvaasVirtualizeTable(dvaasVirtualizeTableOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(201)
				}))
			})
			It(`Invoke DvaasVirtualizeTable successfully`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())

				// Construct an instance of the VirtualizeTableParameterSourceTableDefItem model
				virtualizeTableParameterSourceTableDefItemModel := new(datavirtualizationv1.VirtualizeTableParameterSourceTableDefItem)
				virtualizeTableParameterSourceTableDefItemModel.ColumnName = core.StringPtr("Column1")
				virtualizeTableParameterSourceTableDefItemModel.ColumnType = core.StringPtr("INTEGER")

				// Construct an instance of the VirtualizeTableParameterVirtualTableDefItem model
				virtualizeTableParameterVirtualTableDefItemModel := new(datavirtualizationv1.VirtualizeTableParameterVirtualTableDefItem)
				virtualizeTableParameterVirtualTableDefItemModel.ColumnName = core.StringPtr("Column_1")
				virtualizeTableParameterVirtualTableDefItemModel.ColumnType = core.StringPtr("INTEGER")

				// Construct an instance of the DvaasVirtualizeTableOptions model
				dvaasVirtualizeTableOptionsModel := new(datavirtualizationv1.DvaasVirtualizeTableOptions)
				dvaasVirtualizeTableOptionsModel.SourceName = core.StringPtr("Tab1")
				dvaasVirtualizeTableOptionsModel.SourceTableDef = []datavirtualizationv1.VirtualizeTableParameterSourceTableDefItem{*virtualizeTableParameterSourceTableDefItemModel}
				dvaasVirtualizeTableOptionsModel.Sources = []string{`DB210001:"Hjq1"`}
				dvaasVirtualizeTableOptionsModel.VirtualName = core.StringPtr("Tab1")
				dvaasVirtualizeTableOptionsModel.VirtualSchema = core.StringPtr("dv_ibmid_060000s4y5")
				dvaasVirtualizeTableOptionsModel.VirtualTableDef = []datavirtualizationv1.VirtualizeTableParameterVirtualTableDefItem{*virtualizeTableParameterVirtualTableDefItemModel}
				dvaasVirtualizeTableOptionsModel.IsIncludedColumns = core.StringPtr("Y, Y, N")
				dvaasVirtualizeTableOptionsModel.Replace = core.BoolPtr(false)
				dvaasVirtualizeTableOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := dataVirtualizationService.DvaasVirtualizeTable(dvaasVirtualizeTableOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`DeleteTable(deleteTableOptions *DeleteTableOptions)`, func() {
		deleteTablePath := "/v2/virtualization/tables/testString"
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(deleteTablePath))
					Expect(req.Method).To(Equal("DELETE"))

					Expect(req.URL.Query()["virtual_schema"]).To(Equal([]string{"testString"}))
					res.WriteHeader(204)
				}))
			})
			It(`Invoke DeleteTable successfully`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				response, operationErr := dataVirtualizationService.DeleteTable(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())

				// Construct an instance of the DeleteTableOptions model
				deleteTableOptionsModel := new(datavirtualizationv1.DeleteTableOptions)
				deleteTableOptionsModel.VirtualSchema = core.StringPtr("testString")
				deleteTableOptionsModel.VirtualName = core.StringPtr("testString")
				deleteTableOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				response, operationErr = dataVirtualizationService.DeleteTable(deleteTableOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
			})
			It(`Invoke DeleteTable with error: Operation validation and request error`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())

				// Construct an instance of the DeleteTableOptions model
				deleteTableOptionsModel := new(datavirtualizationv1.DeleteTableOptions)
				deleteTableOptionsModel.VirtualSchema = core.StringPtr("testString")
				deleteTableOptionsModel.VirtualName = core.StringPtr("testString")
				deleteTableOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := dataVirtualizationService.SetServiceURL("")
				Expect(err).To(BeNil())
				response, operationErr := dataVirtualizationService.DeleteTable(deleteTableOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				// Construct a second instance of the DeleteTableOptions model with no property values
				deleteTableOptionsModelNew := new(datavirtualizationv1.DeleteTableOptions)
				// Invoke operation with invalid model (negative test)
				response, operationErr = dataVirtualizationService.DeleteTable(deleteTableOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetPrimaryCatalog(getPrimaryCatalogOptions *GetPrimaryCatalogOptions) - Operation response error`, func() {
		getPrimaryCatalogPath := "/v2/catalog/primary"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getPrimaryCatalogPath))
					Expect(req.Method).To(Equal("GET"))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke GetPrimaryCatalog with error: Operation response processing error`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())

				// Construct an instance of the GetPrimaryCatalogOptions model
				getPrimaryCatalogOptionsModel := new(datavirtualizationv1.GetPrimaryCatalogOptions)
				getPrimaryCatalogOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := dataVirtualizationService.GetPrimaryCatalog(getPrimaryCatalogOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				dataVirtualizationService.EnableRetries(0, 0)
				result, response, operationErr = dataVirtualizationService.GetPrimaryCatalog(getPrimaryCatalogOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetPrimaryCatalog(getPrimaryCatalogOptions *GetPrimaryCatalogOptions)`, func() {
		getPrimaryCatalogPath := "/v2/catalog/primary"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getPrimaryCatalogPath))
					Expect(req.Method).To(Equal("GET"))

					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"entity": {"auto_profiling": true, "bss_account_id": "999", "capacity_limit": 0, "description": "The governed catalog where data assets are synchronized with the Information assets view.", "generator": "Catalog-OMRS-Synced", "is_governed": true, "name": "Primary Catalog"}, "href": "/v2/catalogs/648fb4e0-3f6c-4ce3-afbb-317acc03faa4", "metadata": {"create_time": "2021-01-11T10:37:03Z", "creator_id": "648fb4e01000330999", "guid": "648fb4e0-3f6c-4ce3-afbb-317acc03faa4", "url": "648fb4e0/v2/catalogs/648fb4e0-3f6c-4ce3-afbb-317acc03faa4"}}`)
				}))
			})
			It(`Invoke GetPrimaryCatalog successfully with retries`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())
				dataVirtualizationService.EnableRetries(0, 0)

				// Construct an instance of the GetPrimaryCatalogOptions model
				getPrimaryCatalogOptionsModel := new(datavirtualizationv1.GetPrimaryCatalogOptions)
				getPrimaryCatalogOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := dataVirtualizationService.GetPrimaryCatalogWithContext(ctx, getPrimaryCatalogOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				dataVirtualizationService.DisableRetries()
				result, response, operationErr := dataVirtualizationService.GetPrimaryCatalog(getPrimaryCatalogOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = dataVirtualizationService.GetPrimaryCatalogWithContext(ctx, getPrimaryCatalogOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getPrimaryCatalogPath))
					Expect(req.Method).To(Equal("GET"))

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"entity": {"auto_profiling": true, "bss_account_id": "999", "capacity_limit": 0, "description": "The governed catalog where data assets are synchronized with the Information assets view.", "generator": "Catalog-OMRS-Synced", "is_governed": true, "name": "Primary Catalog"}, "href": "/v2/catalogs/648fb4e0-3f6c-4ce3-afbb-317acc03faa4", "metadata": {"create_time": "2021-01-11T10:37:03Z", "creator_id": "648fb4e01000330999", "guid": "648fb4e0-3f6c-4ce3-afbb-317acc03faa4", "url": "648fb4e0/v2/catalogs/648fb4e0-3f6c-4ce3-afbb-317acc03faa4"}}`)
				}))
			})
			It(`Invoke GetPrimaryCatalog successfully`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := dataVirtualizationService.GetPrimaryCatalog(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the GetPrimaryCatalogOptions model
				getPrimaryCatalogOptionsModel := new(datavirtualizationv1.GetPrimaryCatalogOptions)
				getPrimaryCatalogOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = dataVirtualizationService.GetPrimaryCatalog(getPrimaryCatalogOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke GetPrimaryCatalog with error: Operation request error`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())

				// Construct an instance of the GetPrimaryCatalogOptions model
				getPrimaryCatalogOptionsModel := new(datavirtualizationv1.GetPrimaryCatalogOptions)
				getPrimaryCatalogOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := dataVirtualizationService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := dataVirtualizationService.GetPrimaryCatalog(getPrimaryCatalogOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(200)
				}))
			})
			It(`Invoke GetPrimaryCatalog successfully`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())

				// Construct an instance of the GetPrimaryCatalogOptions model
				getPrimaryCatalogOptionsModel := new(datavirtualizationv1.GetPrimaryCatalogOptions)
				getPrimaryCatalogOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := dataVirtualizationService.GetPrimaryCatalog(getPrimaryCatalogOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`PostPrimaryCatalog(postPrimaryCatalogOptions *PostPrimaryCatalogOptions) - Operation response error`, func() {
		postPrimaryCatalogPath := "/v2/catalog/primary"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(postPrimaryCatalogPath))
					Expect(req.Method).To(Equal("POST"))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(201)
					fmt.Fprintf(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke PostPrimaryCatalog with error: Operation response processing error`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())

				// Construct an instance of the PostPrimaryCatalogOptions model
				postPrimaryCatalogOptionsModel := new(datavirtualizationv1.PostPrimaryCatalogOptions)
				postPrimaryCatalogOptionsModel.GUID = core.StringPtr("d77fc432-9b1a-4938-a2a5-9f37e08041f6")
				postPrimaryCatalogOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := dataVirtualizationService.PostPrimaryCatalog(postPrimaryCatalogOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				dataVirtualizationService.EnableRetries(0, 0)
				result, response, operationErr = dataVirtualizationService.PostPrimaryCatalog(postPrimaryCatalogOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`PostPrimaryCatalog(postPrimaryCatalogOptions *PostPrimaryCatalogOptions)`, func() {
		postPrimaryCatalogPath := "/v2/catalog/primary"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(postPrimaryCatalogPath))
					Expect(req.Method).To(Equal("POST"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(201)
					fmt.Fprintf(res, "%s", `{"guid": "d77fc432-9b1a-4938-a2a5-9f37e08041f6", "name": "Default Catalog", "description": "The governed catalog where data assets are synchronized with the Information assets view."}`)
				}))
			})
			It(`Invoke PostPrimaryCatalog successfully with retries`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())
				dataVirtualizationService.EnableRetries(0, 0)

				// Construct an instance of the PostPrimaryCatalogOptions model
				postPrimaryCatalogOptionsModel := new(datavirtualizationv1.PostPrimaryCatalogOptions)
				postPrimaryCatalogOptionsModel.GUID = core.StringPtr("d77fc432-9b1a-4938-a2a5-9f37e08041f6")
				postPrimaryCatalogOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := dataVirtualizationService.PostPrimaryCatalogWithContext(ctx, postPrimaryCatalogOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				dataVirtualizationService.DisableRetries()
				result, response, operationErr := dataVirtualizationService.PostPrimaryCatalog(postPrimaryCatalogOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = dataVirtualizationService.PostPrimaryCatalogWithContext(ctx, postPrimaryCatalogOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(postPrimaryCatalogPath))
					Expect(req.Method).To(Equal("POST"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(201)
					fmt.Fprintf(res, "%s", `{"guid": "d77fc432-9b1a-4938-a2a5-9f37e08041f6", "name": "Default Catalog", "description": "The governed catalog where data assets are synchronized with the Information assets view."}`)
				}))
			})
			It(`Invoke PostPrimaryCatalog successfully`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := dataVirtualizationService.PostPrimaryCatalog(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the PostPrimaryCatalogOptions model
				postPrimaryCatalogOptionsModel := new(datavirtualizationv1.PostPrimaryCatalogOptions)
				postPrimaryCatalogOptionsModel.GUID = core.StringPtr("d77fc432-9b1a-4938-a2a5-9f37e08041f6")
				postPrimaryCatalogOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = dataVirtualizationService.PostPrimaryCatalog(postPrimaryCatalogOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke PostPrimaryCatalog with error: Operation validation and request error`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())

				// Construct an instance of the PostPrimaryCatalogOptions model
				postPrimaryCatalogOptionsModel := new(datavirtualizationv1.PostPrimaryCatalogOptions)
				postPrimaryCatalogOptionsModel.GUID = core.StringPtr("d77fc432-9b1a-4938-a2a5-9f37e08041f6")
				postPrimaryCatalogOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := dataVirtualizationService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := dataVirtualizationService.PostPrimaryCatalog(postPrimaryCatalogOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the PostPrimaryCatalogOptions model with no property values
				postPrimaryCatalogOptionsModelNew := new(datavirtualizationv1.PostPrimaryCatalogOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = dataVirtualizationService.PostPrimaryCatalog(postPrimaryCatalogOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(201)
				}))
			})
			It(`Invoke PostPrimaryCatalog successfully`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())

				// Construct an instance of the PostPrimaryCatalogOptions model
				postPrimaryCatalogOptionsModel := new(datavirtualizationv1.PostPrimaryCatalogOptions)
				postPrimaryCatalogOptionsModel.GUID = core.StringPtr("d77fc432-9b1a-4938-a2a5-9f37e08041f6")
				postPrimaryCatalogOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := dataVirtualizationService.PostPrimaryCatalog(postPrimaryCatalogOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`DeletePrimaryCatalog(deletePrimaryCatalogOptions *DeletePrimaryCatalogOptions)`, func() {
		deletePrimaryCatalogPath := "/v2/catalog/primary"
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(deletePrimaryCatalogPath))
					Expect(req.Method).To(Equal("DELETE"))

					Expect(req.URL.Query()["guid"]).To(Equal([]string{"d77fc432-9b1a-4938-a2a5-9f37e08041f6"}))
					res.WriteHeader(204)
				}))
			})
			It(`Invoke DeletePrimaryCatalog successfully`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				response, operationErr := dataVirtualizationService.DeletePrimaryCatalog(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())

				// Construct an instance of the DeletePrimaryCatalogOptions model
				deletePrimaryCatalogOptionsModel := new(datavirtualizationv1.DeletePrimaryCatalogOptions)
				deletePrimaryCatalogOptionsModel.GUID = core.StringPtr("d77fc432-9b1a-4938-a2a5-9f37e08041f6")
				deletePrimaryCatalogOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				response, operationErr = dataVirtualizationService.DeletePrimaryCatalog(deletePrimaryCatalogOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
			})
			It(`Invoke DeletePrimaryCatalog with error: Operation validation and request error`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())

				// Construct an instance of the DeletePrimaryCatalogOptions model
				deletePrimaryCatalogOptionsModel := new(datavirtualizationv1.DeletePrimaryCatalogOptions)
				deletePrimaryCatalogOptionsModel.GUID = core.StringPtr("d77fc432-9b1a-4938-a2a5-9f37e08041f6")
				deletePrimaryCatalogOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := dataVirtualizationService.SetServiceURL("")
				Expect(err).To(BeNil())
				response, operationErr := dataVirtualizationService.DeletePrimaryCatalog(deletePrimaryCatalogOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				// Construct a second instance of the DeletePrimaryCatalogOptions model with no property values
				deletePrimaryCatalogOptionsModelNew := new(datavirtualizationv1.DeletePrimaryCatalogOptions)
				// Invoke operation with invalid model (negative test)
				response, operationErr = dataVirtualizationService.DeletePrimaryCatalog(deletePrimaryCatalogOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`PublishAssets(publishAssetsOptions *PublishAssetsOptions) - Operation response error`, func() {
		publishAssetsPath := "/v2/integration/catalog/publish"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(publishAssetsPath))
					Expect(req.Method).To(Equal("POST"))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke PublishAssets with error: Operation response processing error`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())

				// Construct an instance of the PostPrimaryCatalogParametersAssetsItem model
				postPrimaryCatalogParametersAssetsItemModel := new(datavirtualizationv1.PostPrimaryCatalogParametersAssetsItem)
				postPrimaryCatalogParametersAssetsItemModel.Schema = core.StringPtr("db2inst1")
				postPrimaryCatalogParametersAssetsItemModel.Table = core.StringPtr("EMPLOYEE")

				// Construct an instance of the PublishAssetsOptions model
				publishAssetsOptionsModel := new(datavirtualizationv1.PublishAssetsOptions)
				publishAssetsOptionsModel.CatalogID = core.StringPtr("2b6b9fc5-626c-47a9-a836-56b76c0bc826")
				publishAssetsOptionsModel.AllowDuplicates = core.BoolPtr(false)
				publishAssetsOptionsModel.Assets = []datavirtualizationv1.PostPrimaryCatalogParametersAssetsItem{*postPrimaryCatalogParametersAssetsItemModel}
				publishAssetsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := dataVirtualizationService.PublishAssets(publishAssetsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				dataVirtualizationService.EnableRetries(0, 0)
				result, response, operationErr = dataVirtualizationService.PublishAssets(publishAssetsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`PublishAssets(publishAssetsOptions *PublishAssetsOptions)`, func() {
		publishAssetsPath := "/v2/integration/catalog/publish"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(publishAssetsPath))
					Expect(req.Method).To(Equal("POST"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"duplicate_assets": [{"schema_name": "USER999", "table_name": "customer"}], "failed_assets": [{"error_msg": "37fa4a15-1071-4a20-bc9e-0283d3dfb6e", "schema_name": "USER999", "table_name": "customer"}], "published_assets": [{"schema_name": "USER999", "table_name": "customer", "wkc_asset_id": "37fa4a15-1071-4a20-bc9e-0283d3dfb6e1"}]}`)
				}))
			})
			It(`Invoke PublishAssets successfully with retries`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())
				dataVirtualizationService.EnableRetries(0, 0)

				// Construct an instance of the PostPrimaryCatalogParametersAssetsItem model
				postPrimaryCatalogParametersAssetsItemModel := new(datavirtualizationv1.PostPrimaryCatalogParametersAssetsItem)
				postPrimaryCatalogParametersAssetsItemModel.Schema = core.StringPtr("db2inst1")
				postPrimaryCatalogParametersAssetsItemModel.Table = core.StringPtr("EMPLOYEE")

				// Construct an instance of the PublishAssetsOptions model
				publishAssetsOptionsModel := new(datavirtualizationv1.PublishAssetsOptions)
				publishAssetsOptionsModel.CatalogID = core.StringPtr("2b6b9fc5-626c-47a9-a836-56b76c0bc826")
				publishAssetsOptionsModel.AllowDuplicates = core.BoolPtr(false)
				publishAssetsOptionsModel.Assets = []datavirtualizationv1.PostPrimaryCatalogParametersAssetsItem{*postPrimaryCatalogParametersAssetsItemModel}
				publishAssetsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := dataVirtualizationService.PublishAssetsWithContext(ctx, publishAssetsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				dataVirtualizationService.DisableRetries()
				result, response, operationErr := dataVirtualizationService.PublishAssets(publishAssetsOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = dataVirtualizationService.PublishAssetsWithContext(ctx, publishAssetsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(publishAssetsPath))
					Expect(req.Method).To(Equal("POST"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"duplicate_assets": [{"schema_name": "USER999", "table_name": "customer"}], "failed_assets": [{"error_msg": "37fa4a15-1071-4a20-bc9e-0283d3dfb6e", "schema_name": "USER999", "table_name": "customer"}], "published_assets": [{"schema_name": "USER999", "table_name": "customer", "wkc_asset_id": "37fa4a15-1071-4a20-bc9e-0283d3dfb6e1"}]}`)
				}))
			})
			It(`Invoke PublishAssets successfully`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := dataVirtualizationService.PublishAssets(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the PostPrimaryCatalogParametersAssetsItem model
				postPrimaryCatalogParametersAssetsItemModel := new(datavirtualizationv1.PostPrimaryCatalogParametersAssetsItem)
				postPrimaryCatalogParametersAssetsItemModel.Schema = core.StringPtr("db2inst1")
				postPrimaryCatalogParametersAssetsItemModel.Table = core.StringPtr("EMPLOYEE")

				// Construct an instance of the PublishAssetsOptions model
				publishAssetsOptionsModel := new(datavirtualizationv1.PublishAssetsOptions)
				publishAssetsOptionsModel.CatalogID = core.StringPtr("2b6b9fc5-626c-47a9-a836-56b76c0bc826")
				publishAssetsOptionsModel.AllowDuplicates = core.BoolPtr(false)
				publishAssetsOptionsModel.Assets = []datavirtualizationv1.PostPrimaryCatalogParametersAssetsItem{*postPrimaryCatalogParametersAssetsItemModel}
				publishAssetsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = dataVirtualizationService.PublishAssets(publishAssetsOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke PublishAssets with error: Operation validation and request error`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())

				// Construct an instance of the PostPrimaryCatalogParametersAssetsItem model
				postPrimaryCatalogParametersAssetsItemModel := new(datavirtualizationv1.PostPrimaryCatalogParametersAssetsItem)
				postPrimaryCatalogParametersAssetsItemModel.Schema = core.StringPtr("db2inst1")
				postPrimaryCatalogParametersAssetsItemModel.Table = core.StringPtr("EMPLOYEE")

				// Construct an instance of the PublishAssetsOptions model
				publishAssetsOptionsModel := new(datavirtualizationv1.PublishAssetsOptions)
				publishAssetsOptionsModel.CatalogID = core.StringPtr("2b6b9fc5-626c-47a9-a836-56b76c0bc826")
				publishAssetsOptionsModel.AllowDuplicates = core.BoolPtr(false)
				publishAssetsOptionsModel.Assets = []datavirtualizationv1.PostPrimaryCatalogParametersAssetsItem{*postPrimaryCatalogParametersAssetsItemModel}
				publishAssetsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := dataVirtualizationService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := dataVirtualizationService.PublishAssets(publishAssetsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the PublishAssetsOptions model with no property values
				publishAssetsOptionsModelNew := new(datavirtualizationv1.PublishAssetsOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = dataVirtualizationService.PublishAssets(publishAssetsOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(200)
				}))
			})
			It(`Invoke PublishAssets successfully`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())

				// Construct an instance of the PostPrimaryCatalogParametersAssetsItem model
				postPrimaryCatalogParametersAssetsItemModel := new(datavirtualizationv1.PostPrimaryCatalogParametersAssetsItem)
				postPrimaryCatalogParametersAssetsItemModel.Schema = core.StringPtr("db2inst1")
				postPrimaryCatalogParametersAssetsItemModel.Table = core.StringPtr("EMPLOYEE")

				// Construct an instance of the PublishAssetsOptions model
				publishAssetsOptionsModel := new(datavirtualizationv1.PublishAssetsOptions)
				publishAssetsOptionsModel.CatalogID = core.StringPtr("2b6b9fc5-626c-47a9-a836-56b76c0bc826")
				publishAssetsOptionsModel.AllowDuplicates = core.BoolPtr(false)
				publishAssetsOptionsModel.Assets = []datavirtualizationv1.PostPrimaryCatalogParametersAssetsItem{*postPrimaryCatalogParametersAssetsItemModel}
				publishAssetsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := dataVirtualizationService.PublishAssets(publishAssetsOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`Model constructor tests`, func() {
		Context(`Using a service client instance`, func() {
			dataVirtualizationService, _ := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
				URL:           "http://datavirtualizationv1modelgenerator.com",
				Authenticator: &core.NoAuthAuthenticator{},
			})
			It(`Invoke NewAddDatasourceConnectionOptions successfully`, func() {
				// Construct an instance of the PostDatasourceConnectionParametersProperties model
				postDatasourceConnectionParametersPropertiesModel := new(datavirtualizationv1.PostDatasourceConnectionParametersProperties)
				Expect(postDatasourceConnectionParametersPropertiesModel).ToNot(BeNil())
				postDatasourceConnectionParametersPropertiesModel.AccessToken = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.AccountName = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.APIKey = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.AuthType = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.ClientID = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.ClientSecret = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Collection = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Credentials = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Database = core.StringPtr("TPCDS")
				postDatasourceConnectionParametersPropertiesModel.Host = core.StringPtr("192.168.0.1")
				postDatasourceConnectionParametersPropertiesModel.HTTPPath = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.JarUris = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.JdbcDriver = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.JdbcURL = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Password = core.StringPtr("password")
				postDatasourceConnectionParametersPropertiesModel.Port = core.StringPtr("50000")
				postDatasourceConnectionParametersPropertiesModel.ProjectID = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Properties = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.RefreshToken = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Role = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.SapGatewayURL = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Server = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.ServiceName = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Sid = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Ssl = core.StringPtr("false")
				postDatasourceConnectionParametersPropertiesModel.SslCertificate = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.SslCertificateHost = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.SslCertificateValidation = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Username = core.StringPtr("db2inst1")
				postDatasourceConnectionParametersPropertiesModel.Warehouse = core.StringPtr("testString")
				Expect(postDatasourceConnectionParametersPropertiesModel.AccessToken).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersPropertiesModel.AccountName).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersPropertiesModel.APIKey).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersPropertiesModel.AuthType).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersPropertiesModel.ClientID).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersPropertiesModel.ClientSecret).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersPropertiesModel.Collection).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersPropertiesModel.Credentials).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersPropertiesModel.Database).To(Equal(core.StringPtr("TPCDS")))
				Expect(postDatasourceConnectionParametersPropertiesModel.Host).To(Equal(core.StringPtr("192.168.0.1")))
				Expect(postDatasourceConnectionParametersPropertiesModel.HTTPPath).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersPropertiesModel.JarUris).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersPropertiesModel.JdbcDriver).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersPropertiesModel.JdbcURL).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersPropertiesModel.Password).To(Equal(core.StringPtr("password")))
				Expect(postDatasourceConnectionParametersPropertiesModel.Port).To(Equal(core.StringPtr("50000")))
				Expect(postDatasourceConnectionParametersPropertiesModel.ProjectID).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersPropertiesModel.Properties).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersPropertiesModel.RefreshToken).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersPropertiesModel.Role).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersPropertiesModel.SapGatewayURL).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersPropertiesModel.Server).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersPropertiesModel.ServiceName).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersPropertiesModel.Sid).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersPropertiesModel.Ssl).To(Equal(core.StringPtr("false")))
				Expect(postDatasourceConnectionParametersPropertiesModel.SslCertificate).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersPropertiesModel.SslCertificateHost).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersPropertiesModel.SslCertificateValidation).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersPropertiesModel.Username).To(Equal(core.StringPtr("db2inst1")))
				Expect(postDatasourceConnectionParametersPropertiesModel.Warehouse).To(Equal(core.StringPtr("testString")))

				// Construct an instance of the AddDatasourceConnectionOptions model
				addDatasourceConnectionOptionsDatasourceType := "DB2"
				addDatasourceConnectionOptionsName := "DB2"
				addDatasourceConnectionOptionsOriginCountry := "us"
				var addDatasourceConnectionOptionsProperties *datavirtualizationv1.PostDatasourceConnectionParametersProperties = nil
				addDatasourceConnectionOptionsModel := dataVirtualizationService.NewAddDatasourceConnectionOptions(addDatasourceConnectionOptionsDatasourceType, addDatasourceConnectionOptionsName, addDatasourceConnectionOptionsOriginCountry, addDatasourceConnectionOptionsProperties)
				addDatasourceConnectionOptionsModel.SetDatasourceType("DB2")
				addDatasourceConnectionOptionsModel.SetName("DB2")
				addDatasourceConnectionOptionsModel.SetOriginCountry("us")
				addDatasourceConnectionOptionsModel.SetProperties(postDatasourceConnectionParametersPropertiesModel)
				addDatasourceConnectionOptionsModel.SetAssetCategory("testString")
				addDatasourceConnectionOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(addDatasourceConnectionOptionsModel).ToNot(BeNil())
				Expect(addDatasourceConnectionOptionsModel.DatasourceType).To(Equal(core.StringPtr("DB2")))
				Expect(addDatasourceConnectionOptionsModel.Name).To(Equal(core.StringPtr("DB2")))
				Expect(addDatasourceConnectionOptionsModel.OriginCountry).To(Equal(core.StringPtr("us")))
				Expect(addDatasourceConnectionOptionsModel.Properties).To(Equal(postDatasourceConnectionParametersPropertiesModel))
				Expect(addDatasourceConnectionOptionsModel.AssetCategory).To(Equal(core.StringPtr("testString")))
				Expect(addDatasourceConnectionOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewCheckPolicyStatusV2Options successfully`, func() {
				// Construct an instance of the CheckPolicyStatusV2Options model
				checkPolicyStatusV2OptionsModel := dataVirtualizationService.NewCheckPolicyStatusV2Options()
				checkPolicyStatusV2OptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(checkPolicyStatusV2OptionsModel).ToNot(BeNil())
				Expect(checkPolicyStatusV2OptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewDeleteDatasourceConnectionOptions successfully`, func() {
				// Construct an instance of the DeleteDatasourceConnectionOptions model
				connectionID := "75e4d01b-7417-4abc-b267-8ffb393fb970"
				deleteDatasourceConnectionOptionsModel := dataVirtualizationService.NewDeleteDatasourceConnectionOptions(connectionID)
				deleteDatasourceConnectionOptionsModel.SetConnectionID("75e4d01b-7417-4abc-b267-8ffb393fb970")
				deleteDatasourceConnectionOptionsModel.SetCid("DB210013")
				deleteDatasourceConnectionOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(deleteDatasourceConnectionOptionsModel).ToNot(BeNil())
				Expect(deleteDatasourceConnectionOptionsModel.ConnectionID).To(Equal(core.StringPtr("75e4d01b-7417-4abc-b267-8ffb393fb970")))
				Expect(deleteDatasourceConnectionOptionsModel.Cid).To(Equal(core.StringPtr("DB210013")))
				Expect(deleteDatasourceConnectionOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewDeletePrimaryCatalogOptions successfully`, func() {
				// Construct an instance of the DeletePrimaryCatalogOptions model
				guid := "d77fc432-9b1a-4938-a2a5-9f37e08041f6"
				deletePrimaryCatalogOptionsModel := dataVirtualizationService.NewDeletePrimaryCatalogOptions(guid)
				deletePrimaryCatalogOptionsModel.SetGUID("d77fc432-9b1a-4938-a2a5-9f37e08041f6")
				deletePrimaryCatalogOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(deletePrimaryCatalogOptionsModel).ToNot(BeNil())
				Expect(deletePrimaryCatalogOptionsModel.GUID).To(Equal(core.StringPtr("d77fc432-9b1a-4938-a2a5-9f37e08041f6")))
				Expect(deletePrimaryCatalogOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewDeleteTableOptions successfully`, func() {
				// Construct an instance of the DeleteTableOptions model
				virtualSchema := "testString"
				virtualName := "testString"
				deleteTableOptionsModel := dataVirtualizationService.NewDeleteTableOptions(virtualSchema, virtualName)
				deleteTableOptionsModel.SetVirtualSchema("testString")
				deleteTableOptionsModel.SetVirtualName("testString")
				deleteTableOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(deleteTableOptionsModel).ToNot(BeNil())
				Expect(deleteTableOptionsModel.VirtualSchema).To(Equal(core.StringPtr("testString")))
				Expect(deleteTableOptionsModel.VirtualName).To(Equal(core.StringPtr("testString")))
				Expect(deleteTableOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewDvaasRevokeRoleFromTableOptions successfully`, func() {
				// Construct an instance of the DvaasRevokeRoleFromTableOptions model
				roleName := "DV_ENGINEER"
				tableName := "EMPLOYEE"
				tableSchema := "dv_ibmid_060000s4y5"
				dvaasRevokeRoleFromTableOptionsModel := dataVirtualizationService.NewDvaasRevokeRoleFromTableOptions(roleName, tableName, tableSchema)
				dvaasRevokeRoleFromTableOptionsModel.SetRoleName("DV_ENGINEER")
				dvaasRevokeRoleFromTableOptionsModel.SetTableName("EMPLOYEE")
				dvaasRevokeRoleFromTableOptionsModel.SetTableSchema("dv_ibmid_060000s4y5")
				dvaasRevokeRoleFromTableOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(dvaasRevokeRoleFromTableOptionsModel).ToNot(BeNil())
				Expect(dvaasRevokeRoleFromTableOptionsModel.RoleName).To(Equal(core.StringPtr("DV_ENGINEER")))
				Expect(dvaasRevokeRoleFromTableOptionsModel.TableName).To(Equal(core.StringPtr("EMPLOYEE")))
				Expect(dvaasRevokeRoleFromTableOptionsModel.TableSchema).To(Equal(core.StringPtr("dv_ibmid_060000s4y5")))
				Expect(dvaasRevokeRoleFromTableOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewDvaasVirtualizeTableOptions successfully`, func() {
				// Construct an instance of the VirtualizeTableParameterSourceTableDefItem model
				virtualizeTableParameterSourceTableDefItemModel := new(datavirtualizationv1.VirtualizeTableParameterSourceTableDefItem)
				Expect(virtualizeTableParameterSourceTableDefItemModel).ToNot(BeNil())
				virtualizeTableParameterSourceTableDefItemModel.ColumnName = core.StringPtr("Column1")
				virtualizeTableParameterSourceTableDefItemModel.ColumnType = core.StringPtr("INTEGER")
				Expect(virtualizeTableParameterSourceTableDefItemModel.ColumnName).To(Equal(core.StringPtr("Column1")))
				Expect(virtualizeTableParameterSourceTableDefItemModel.ColumnType).To(Equal(core.StringPtr("INTEGER")))

				// Construct an instance of the VirtualizeTableParameterVirtualTableDefItem model
				virtualizeTableParameterVirtualTableDefItemModel := new(datavirtualizationv1.VirtualizeTableParameterVirtualTableDefItem)
				Expect(virtualizeTableParameterVirtualTableDefItemModel).ToNot(BeNil())
				virtualizeTableParameterVirtualTableDefItemModel.ColumnName = core.StringPtr("Column_1")
				virtualizeTableParameterVirtualTableDefItemModel.ColumnType = core.StringPtr("INTEGER")
				Expect(virtualizeTableParameterVirtualTableDefItemModel.ColumnName).To(Equal(core.StringPtr("Column_1")))
				Expect(virtualizeTableParameterVirtualTableDefItemModel.ColumnType).To(Equal(core.StringPtr("INTEGER")))

				// Construct an instance of the DvaasVirtualizeTableOptions model
				dvaasVirtualizeTableOptionsSourceName := "Tab1"
				dvaasVirtualizeTableOptionsSourceTableDef := []datavirtualizationv1.VirtualizeTableParameterSourceTableDefItem{}
				dvaasVirtualizeTableOptionsSources := []string{`DB210001:"Hjq1"`}
				dvaasVirtualizeTableOptionsVirtualName := "Tab1"
				dvaasVirtualizeTableOptionsVirtualSchema := "dv_ibmid_060000s4y5"
				dvaasVirtualizeTableOptionsVirtualTableDef := []datavirtualizationv1.VirtualizeTableParameterVirtualTableDefItem{}
				dvaasVirtualizeTableOptionsModel := dataVirtualizationService.NewDvaasVirtualizeTableOptions(dvaasVirtualizeTableOptionsSourceName, dvaasVirtualizeTableOptionsSourceTableDef, dvaasVirtualizeTableOptionsSources, dvaasVirtualizeTableOptionsVirtualName, dvaasVirtualizeTableOptionsVirtualSchema, dvaasVirtualizeTableOptionsVirtualTableDef)
				dvaasVirtualizeTableOptionsModel.SetSourceName("Tab1")
				dvaasVirtualizeTableOptionsModel.SetSourceTableDef([]datavirtualizationv1.VirtualizeTableParameterSourceTableDefItem{*virtualizeTableParameterSourceTableDefItemModel})
				dvaasVirtualizeTableOptionsModel.SetSources([]string{`DB210001:"Hjq1"`})
				dvaasVirtualizeTableOptionsModel.SetVirtualName("Tab1")
				dvaasVirtualizeTableOptionsModel.SetVirtualSchema("dv_ibmid_060000s4y5")
				dvaasVirtualizeTableOptionsModel.SetVirtualTableDef([]datavirtualizationv1.VirtualizeTableParameterVirtualTableDefItem{*virtualizeTableParameterVirtualTableDefItemModel})
				dvaasVirtualizeTableOptionsModel.SetIsIncludedColumns("Y, Y, N")
				dvaasVirtualizeTableOptionsModel.SetReplace(false)
				dvaasVirtualizeTableOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(dvaasVirtualizeTableOptionsModel).ToNot(BeNil())
				Expect(dvaasVirtualizeTableOptionsModel.SourceName).To(Equal(core.StringPtr("Tab1")))
				Expect(dvaasVirtualizeTableOptionsModel.SourceTableDef).To(Equal([]datavirtualizationv1.VirtualizeTableParameterSourceTableDefItem{*virtualizeTableParameterSourceTableDefItemModel}))
				Expect(dvaasVirtualizeTableOptionsModel.Sources).To(Equal([]string{`DB210001:"Hjq1"`}))
				Expect(dvaasVirtualizeTableOptionsModel.VirtualName).To(Equal(core.StringPtr("Tab1")))
				Expect(dvaasVirtualizeTableOptionsModel.VirtualSchema).To(Equal(core.StringPtr("dv_ibmid_060000s4y5")))
				Expect(dvaasVirtualizeTableOptionsModel.VirtualTableDef).To(Equal([]datavirtualizationv1.VirtualizeTableParameterVirtualTableDefItem{*virtualizeTableParameterVirtualTableDefItemModel}))
				Expect(dvaasVirtualizeTableOptionsModel.IsIncludedColumns).To(Equal(core.StringPtr("Y, Y, N")))
				Expect(dvaasVirtualizeTableOptionsModel.Replace).To(Equal(core.BoolPtr(false)))
				Expect(dvaasVirtualizeTableOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewGetPrimaryCatalogOptions successfully`, func() {
				// Construct an instance of the GetPrimaryCatalogOptions model
				getPrimaryCatalogOptionsModel := dataVirtualizationService.NewGetPrimaryCatalogOptions()
				getPrimaryCatalogOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(getPrimaryCatalogOptionsModel).ToNot(BeNil())
				Expect(getPrimaryCatalogOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewGrantRolesToVirtualizedTableOptions successfully`, func() {
				// Construct an instance of the GrantRolesToVirtualizedTableOptions model
				grantRolesToVirtualizedTableOptionsTableName := "EMPLOYEE"
				grantRolesToVirtualizedTableOptionsTableSchema := "dv_ibmid_060000s4y5"
				grantRolesToVirtualizedTableOptionsModel := dataVirtualizationService.NewGrantRolesToVirtualizedTableOptions(grantRolesToVirtualizedTableOptionsTableName, grantRolesToVirtualizedTableOptionsTableSchema)
				grantRolesToVirtualizedTableOptionsModel.SetTableName("EMPLOYEE")
				grantRolesToVirtualizedTableOptionsModel.SetTableSchema("dv_ibmid_060000s4y5")
				grantRolesToVirtualizedTableOptionsModel.SetRoleName("PUBLIC")
				grantRolesToVirtualizedTableOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(grantRolesToVirtualizedTableOptionsModel).ToNot(BeNil())
				Expect(grantRolesToVirtualizedTableOptionsModel.TableName).To(Equal(core.StringPtr("EMPLOYEE")))
				Expect(grantRolesToVirtualizedTableOptionsModel.TableSchema).To(Equal(core.StringPtr("dv_ibmid_060000s4y5")))
				Expect(grantRolesToVirtualizedTableOptionsModel.RoleName).To(Equal(core.StringPtr("PUBLIC")))
				Expect(grantRolesToVirtualizedTableOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewGrantUserToVirtualTableOptions successfully`, func() {
				// Construct an instance of the GrantUserToVirtualTableOptions model
				grantUserToVirtualTableOptionsTableName := "EMPLOYEE"
				grantUserToVirtualTableOptionsTableSchema := "dv_ibmid_060000s4y5"
				grantUserToVirtualTableOptionsAuthid := "PUBLIC"
				grantUserToVirtualTableOptionsModel := dataVirtualizationService.NewGrantUserToVirtualTableOptions(grantUserToVirtualTableOptionsTableName, grantUserToVirtualTableOptionsTableSchema, grantUserToVirtualTableOptionsAuthid)
				grantUserToVirtualTableOptionsModel.SetTableName("EMPLOYEE")
				grantUserToVirtualTableOptionsModel.SetTableSchema("dv_ibmid_060000s4y5")
				grantUserToVirtualTableOptionsModel.SetAuthid("PUBLIC")
				grantUserToVirtualTableOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(grantUserToVirtualTableOptionsModel).ToNot(BeNil())
				Expect(grantUserToVirtualTableOptionsModel.TableName).To(Equal(core.StringPtr("EMPLOYEE")))
				Expect(grantUserToVirtualTableOptionsModel.TableSchema).To(Equal(core.StringPtr("dv_ibmid_060000s4y5")))
				Expect(grantUserToVirtualTableOptionsModel.Authid).To(Equal(core.StringPtr("PUBLIC")))
				Expect(grantUserToVirtualTableOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewListDatasourceConnectionsOptions successfully`, func() {
				// Construct an instance of the ListDatasourceConnectionsOptions model
				listDatasourceConnectionsOptionsModel := dataVirtualizationService.NewListDatasourceConnectionsOptions()
				listDatasourceConnectionsOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(listDatasourceConnectionsOptionsModel).ToNot(BeNil())
				Expect(listDatasourceConnectionsOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewListTablesForRoleOptions successfully`, func() {
				// Construct an instance of the ListTablesForRoleOptions model
				rolename := "MANAGER | STEWARD | ENGINEER | USER"
				listTablesForRoleOptionsModel := dataVirtualizationService.NewListTablesForRoleOptions(rolename)
				listTablesForRoleOptionsModel.SetRolename("MANAGER | STEWARD | ENGINEER | USER")
				listTablesForRoleOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(listTablesForRoleOptionsModel).ToNot(BeNil())
				Expect(listTablesForRoleOptionsModel.Rolename).To(Equal(core.StringPtr("MANAGER | STEWARD | ENGINEER | USER")))
				Expect(listTablesForRoleOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewPostPrimaryCatalogOptions successfully`, func() {
				// Construct an instance of the PostPrimaryCatalogOptions model
				postPrimaryCatalogOptionsGUID := "d77fc432-9b1a-4938-a2a5-9f37e08041f6"
				postPrimaryCatalogOptionsModel := dataVirtualizationService.NewPostPrimaryCatalogOptions(postPrimaryCatalogOptionsGUID)
				postPrimaryCatalogOptionsModel.SetGUID("d77fc432-9b1a-4938-a2a5-9f37e08041f6")
				postPrimaryCatalogOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(postPrimaryCatalogOptionsModel).ToNot(BeNil())
				Expect(postPrimaryCatalogOptionsModel.GUID).To(Equal(core.StringPtr("d77fc432-9b1a-4938-a2a5-9f37e08041f6")))
				Expect(postPrimaryCatalogOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewPostPrimaryCatalogParametersAssetsItem successfully`, func() {
				schema := "db2inst1"
				table := "EMPLOYEE"
				_model, err := dataVirtualizationService.NewPostPrimaryCatalogParametersAssetsItem(schema, table)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewPublishAssetsOptions successfully`, func() {
				// Construct an instance of the PostPrimaryCatalogParametersAssetsItem model
				postPrimaryCatalogParametersAssetsItemModel := new(datavirtualizationv1.PostPrimaryCatalogParametersAssetsItem)
				Expect(postPrimaryCatalogParametersAssetsItemModel).ToNot(BeNil())
				postPrimaryCatalogParametersAssetsItemModel.Schema = core.StringPtr("db2inst1")
				postPrimaryCatalogParametersAssetsItemModel.Table = core.StringPtr("EMPLOYEE")
				Expect(postPrimaryCatalogParametersAssetsItemModel.Schema).To(Equal(core.StringPtr("db2inst1")))
				Expect(postPrimaryCatalogParametersAssetsItemModel.Table).To(Equal(core.StringPtr("EMPLOYEE")))

				// Construct an instance of the PublishAssetsOptions model
				publishAssetsOptionsCatalogID := "2b6b9fc5-626c-47a9-a836-56b76c0bc826"
				publishAssetsOptionsAllowDuplicates := false
				publishAssetsOptionsAssets := []datavirtualizationv1.PostPrimaryCatalogParametersAssetsItem{}
				publishAssetsOptionsModel := dataVirtualizationService.NewPublishAssetsOptions(publishAssetsOptionsCatalogID, publishAssetsOptionsAllowDuplicates, publishAssetsOptionsAssets)
				publishAssetsOptionsModel.SetCatalogID("2b6b9fc5-626c-47a9-a836-56b76c0bc826")
				publishAssetsOptionsModel.SetAllowDuplicates(false)
				publishAssetsOptionsModel.SetAssets([]datavirtualizationv1.PostPrimaryCatalogParametersAssetsItem{*postPrimaryCatalogParametersAssetsItemModel})
				publishAssetsOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(publishAssetsOptionsModel).ToNot(BeNil())
				Expect(publishAssetsOptionsModel.CatalogID).To(Equal(core.StringPtr("2b6b9fc5-626c-47a9-a836-56b76c0bc826")))
				Expect(publishAssetsOptionsModel.AllowDuplicates).To(Equal(core.BoolPtr(false)))
				Expect(publishAssetsOptionsModel.Assets).To(Equal([]datavirtualizationv1.PostPrimaryCatalogParametersAssetsItem{*postPrimaryCatalogParametersAssetsItemModel}))
				Expect(publishAssetsOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewRevokeUserFromObjectOptions successfully`, func() {
				// Construct an instance of the RevokeUserFromObjectOptions model
				authid := "PUBLIC"
				tableName := "EMPLOYEE"
				tableSchema := "dv_ibmid_060000s4y5"
				revokeUserFromObjectOptionsModel := dataVirtualizationService.NewRevokeUserFromObjectOptions(authid, tableName, tableSchema)
				revokeUserFromObjectOptionsModel.SetAuthid("PUBLIC")
				revokeUserFromObjectOptionsModel.SetTableName("EMPLOYEE")
				revokeUserFromObjectOptionsModel.SetTableSchema("dv_ibmid_060000s4y5")
				revokeUserFromObjectOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(revokeUserFromObjectOptionsModel).ToNot(BeNil())
				Expect(revokeUserFromObjectOptionsModel.Authid).To(Equal(core.StringPtr("PUBLIC")))
				Expect(revokeUserFromObjectOptionsModel.TableName).To(Equal(core.StringPtr("EMPLOYEE")))
				Expect(revokeUserFromObjectOptionsModel.TableSchema).To(Equal(core.StringPtr("dv_ibmid_060000s4y5")))
				Expect(revokeUserFromObjectOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewTurnOnPolicyV2Options successfully`, func() {
				// Construct an instance of the TurnOnPolicyV2Options model
				status := "enabled"
				turnOnPolicyV2OptionsModel := dataVirtualizationService.NewTurnOnPolicyV2Options(status)
				turnOnPolicyV2OptionsModel.SetStatus("enabled")
				turnOnPolicyV2OptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(turnOnPolicyV2OptionsModel).ToNot(BeNil())
				Expect(turnOnPolicyV2OptionsModel.Status).To(Equal(core.StringPtr("enabled")))
				Expect(turnOnPolicyV2OptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewVirtualizeTableParameterSourceTableDefItem successfully`, func() {
				columnName := "Column1"
				columnType := "INTEGER"
				_model, err := dataVirtualizationService.NewVirtualizeTableParameterSourceTableDefItem(columnName, columnType)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewVirtualizeTableParameterVirtualTableDefItem successfully`, func() {
				columnName := "Column_1"
				columnType := "INTEGER"
				_model, err := dataVirtualizationService.NewVirtualizeTableParameterVirtualTableDefItem(columnName, columnType)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
		})
	})
	Describe(`Utility function tests`, func() {
		It(`Invoke CreateMockByteArray() successfully`, func() {
			mockByteArray := CreateMockByteArray("This is a test")
			Expect(mockByteArray).ToNot(BeNil())
		})
		It(`Invoke CreateMockUUID() successfully`, func() {
			mockUUID := CreateMockUUID("9fab83da-98cb-4f18-a7ba-b6f0435c9673")
			Expect(mockUUID).ToNot(BeNil())
		})
		It(`Invoke CreateMockReader() successfully`, func() {
			mockReader := CreateMockReader("This is a test.")
			Expect(mockReader).ToNot(BeNil())
		})
		It(`Invoke CreateMockDate() successfully`, func() {
			mockDate := CreateMockDate("2019-01-01")
			Expect(mockDate).ToNot(BeNil())
		})
		It(`Invoke CreateMockDateTime() successfully`, func() {
			mockDateTime := CreateMockDateTime("2019-01-01T12:00:00.000Z")
			Expect(mockDateTime).ToNot(BeNil())
		})
	})
})

//
// Utility functions used by the generated test code
//

func CreateMockByteArray(mockData string) *[]byte {
	ba := make([]byte, 0)
	ba = append(ba, mockData...)
	return &ba
}

func CreateMockUUID(mockData string) *strfmt.UUID {
	uuid := strfmt.UUID(mockData)
	return &uuid
}

func CreateMockReader(mockData string) io.ReadCloser {
	return ioutil.NopCloser(bytes.NewReader([]byte(mockData)))
}

func CreateMockDate(mockData string) *strfmt.Date {
	d, err := core.ParseDate(mockData)
	if err != nil {
		return nil
	}
	return &d
}

func CreateMockDateTime(mockData string) *strfmt.DateTime {
	d, err := core.ParseDateTime(mockData)
	if err != nil {
		return nil
	}
	return &d
}

func SetTestEnvironment(testEnvironment map[string]string) {
	for key, value := range testEnvironment {
		os.Setenv(key, value)
	}
}

func ClearTestEnvironment(testEnvironment map[string]string) {
	for key := range testEnvironment {
		os.Unsetenv(key)
	}
}
