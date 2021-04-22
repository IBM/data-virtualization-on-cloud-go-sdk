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
	"github.com/IBM/go-sdk-core/v4/core"
	"github.com/go-openapi/strfmt"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/watson-developer-cloud/go-sdk/datavirtualizationv1"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"time"
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
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
				})
				Expect(dataVirtualizationService).ToNot(BeNil())
				Expect(serviceErr).To(BeNil())
				ClearTestEnvironment(testEnvironment)
			})
			It(`Create service client using external config and set url from constructor successfully`, func() {
				SetTestEnvironment(testEnvironment)
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL: "https://testService/api",
				})
				Expect(dataVirtualizationService).ToNot(BeNil())
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService.Service.GetServiceURL()).To(Equal("https://testService/api"))
				ClearTestEnvironment(testEnvironment)
			})
			It(`Create service client using external config and set url programatically successfully`, func() {
				SetTestEnvironment(testEnvironment)
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
				})
				err := dataVirtualizationService.SetServiceURL("https://testService/api")
				Expect(err).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService.Service.GetServiceURL()).To(Equal("https://testService/api"))
				ClearTestEnvironment(testEnvironment)
			})
		})
		Context(`Using external config, construct service client instances with error: Invalid Auth`, func() {
			// Map containing environment variables used in testing.
			var testEnvironment = map[string]string{
				"DATA_VIRTUALIZATION_URL": "https://datavirtualizationv1/api",
				"DATA_VIRTUALIZATION_AUTH_TYPE": "someOtherAuth",
			}

			SetTestEnvironment(testEnvironment)
			dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
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
			dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
				URL: "{BAD_URL_STRING",
			})

			It(`Instantiate service client with error`, func() {
				Expect(dataVirtualizationService).To(BeNil())
				Expect(serviceErr).ToNot(BeNil())
				ClearTestEnvironment(testEnvironment)
			})
		})
	})
	Describe(`GetDatasourceConnections(getDatasourceConnectionsOptions *GetDatasourceConnectionsOptions) - Operation response error`, func() {
		getDatasourceConnectionsPath := "/v2/datasource_connections"
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getDatasourceConnectionsPath))
					Expect(req.Method).To(Equal("GET"))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke GetDatasourceConnections with error: Operation response processing error`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())

				// Construct an instance of the GetDatasourceConnectionsOptions model
				getDatasourceConnectionsOptionsModel := new(datavirtualizationv1.GetDatasourceConnectionsOptions)
				getDatasourceConnectionsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := dataVirtualizationService.GetDatasourceConnections(getDatasourceConnectionsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				dataVirtualizationService.EnableRetries(0, 0)
				result, response, operationErr = dataVirtualizationService.GetDatasourceConnections(getDatasourceConnectionsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})

	Describe(`GetDatasourceConnections(getDatasourceConnectionsOptions *GetDatasourceConnectionsOptions)`, func() {
		getDatasourceConnectionsPath := "/v2/datasource_connections"
		var serverSleepTime time.Duration
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				serverSleepTime = 0
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getDatasourceConnectionsPath))
					Expect(req.Method).To(Equal("GET"))

					// Sleep a short time to support a timeout test
					time.Sleep(serverSleepTime)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"datasource_nodes_array": [{"node_name": "NodeName", "node_description": "NodeDescription", "agent_class": "AgentClass", "hostname": "Hostname", "port": "Port", "os_user": "OsUser", "is_docker": "IsDocker", "dscount": "Dscount", "data_sources": [{"cid": "Cid", "dbname": "Dbname", "srchostname": "Srchostname", "srcport": "Srcport", "srctype": "Srctype", "usr": "Usr", "uri": "URI", "status": "Status", "connection_name": "ConnectionName"}]}]}`)
				}))
			})
			It(`Invoke GetDatasourceConnections successfully`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())
				dataVirtualizationService.EnableRetries(0, 0)

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := dataVirtualizationService.GetDatasourceConnections(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the GetDatasourceConnectionsOptions model
				getDatasourceConnectionsOptionsModel := new(datavirtualizationv1.GetDatasourceConnectionsOptions)
				getDatasourceConnectionsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = dataVirtualizationService.GetDatasourceConnections(getDatasourceConnectionsOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				serverSleepTime = 100 * time.Millisecond
				_, _, operationErr = dataVirtualizationService.GetDatasourceConnectionsWithContext(ctx, getDatasourceConnectionsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
				serverSleepTime = time.Duration(0)

				// Disable retries and test again
				dataVirtualizationService.DisableRetries()
				result, response, operationErr = dataVirtualizationService.GetDatasourceConnections(getDatasourceConnectionsOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				serverSleepTime = 100 * time.Millisecond
				_, _, operationErr = dataVirtualizationService.GetDatasourceConnectionsWithContext(ctx, getDatasourceConnectionsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
				serverSleepTime = time.Duration(0)
			})
			It(`Invoke GetDatasourceConnections with error: Operation request error`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())

				// Construct an instance of the GetDatasourceConnectionsOptions model
				getDatasourceConnectionsOptionsModel := new(datavirtualizationv1.GetDatasourceConnectionsOptions)
				getDatasourceConnectionsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := dataVirtualizationService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := dataVirtualizationService.GetDatasourceConnections(getDatasourceConnectionsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`AddDatasourceConnection(addDatasourceConnectionOptions *AddDatasourceConnectionOptions) - Operation response error`, func() {
		addDatasourceConnectionPath := "/v2/datasource_connections"
		Context(`Using mock server endpoint`, func() {
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
				postDatasourceConnectionParametersPropertiesModel.ApiKey = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.AuthType = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.ClientID = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.ClientSecret = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Collection = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Credentials = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Database = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Host = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.HttpPath = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.JarUris = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.JdbcDriver = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.JdbcURL = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Password = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Port = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.ProjectID = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Properties = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.RefreshToken = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Role = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.SapGatewayURL = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Server = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.ServiceName = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Sid = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Ssl = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.SslCertificate = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.SslCertificateHost = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.SslCertificateValidation = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Username = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Warehouse = core.StringPtr("testString")

				// Construct an instance of the AddDatasourceConnectionOptions model
				addDatasourceConnectionOptionsModel := new(datavirtualizationv1.AddDatasourceConnectionOptions)
				addDatasourceConnectionOptionsModel.DatasourceType = core.StringPtr("testString")
				addDatasourceConnectionOptionsModel.Name = core.StringPtr("testString")
				addDatasourceConnectionOptionsModel.OriginCountry = core.StringPtr("testString")
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
		addDatasourceConnectionPath := "/v2/datasource_connections"
		var serverSleepTime time.Duration
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				serverSleepTime = 0
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
					time.Sleep(serverSleepTime)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(201)
					fmt.Fprintf(res, "%s", `{"datasource_type": "DatasourceType", "name": "Name"}`)
				}))
			})
			It(`Invoke AddDatasourceConnection successfully`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())
				dataVirtualizationService.EnableRetries(0, 0)

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := dataVirtualizationService.AddDatasourceConnection(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the PostDatasourceConnectionParametersProperties model
				postDatasourceConnectionParametersPropertiesModel := new(datavirtualizationv1.PostDatasourceConnectionParametersProperties)
				postDatasourceConnectionParametersPropertiesModel.AccessToken = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.AccountName = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.ApiKey = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.AuthType = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.ClientID = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.ClientSecret = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Collection = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Credentials = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Database = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Host = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.HttpPath = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.JarUris = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.JdbcDriver = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.JdbcURL = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Password = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Port = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.ProjectID = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Properties = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.RefreshToken = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Role = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.SapGatewayURL = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Server = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.ServiceName = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Sid = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Ssl = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.SslCertificate = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.SslCertificateHost = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.SslCertificateValidation = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Username = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Warehouse = core.StringPtr("testString")

				// Construct an instance of the AddDatasourceConnectionOptions model
				addDatasourceConnectionOptionsModel := new(datavirtualizationv1.AddDatasourceConnectionOptions)
				addDatasourceConnectionOptionsModel.DatasourceType = core.StringPtr("testString")
				addDatasourceConnectionOptionsModel.Name = core.StringPtr("testString")
				addDatasourceConnectionOptionsModel.OriginCountry = core.StringPtr("testString")
				addDatasourceConnectionOptionsModel.Properties = postDatasourceConnectionParametersPropertiesModel
				addDatasourceConnectionOptionsModel.AssetCategory = core.StringPtr("testString")
				addDatasourceConnectionOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = dataVirtualizationService.AddDatasourceConnection(addDatasourceConnectionOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				serverSleepTime = 100 * time.Millisecond
				_, _, operationErr = dataVirtualizationService.AddDatasourceConnectionWithContext(ctx, addDatasourceConnectionOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
				serverSleepTime = time.Duration(0)

				// Disable retries and test again
				dataVirtualizationService.DisableRetries()
				result, response, operationErr = dataVirtualizationService.AddDatasourceConnection(addDatasourceConnectionOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				serverSleepTime = 100 * time.Millisecond
				_, _, operationErr = dataVirtualizationService.AddDatasourceConnectionWithContext(ctx, addDatasourceConnectionOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
				serverSleepTime = time.Duration(0)
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
				postDatasourceConnectionParametersPropertiesModel.ApiKey = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.AuthType = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.ClientID = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.ClientSecret = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Collection = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Credentials = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Database = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Host = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.HttpPath = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.JarUris = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.JdbcDriver = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.JdbcURL = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Password = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Port = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.ProjectID = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Properties = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.RefreshToken = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Role = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.SapGatewayURL = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Server = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.ServiceName = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Sid = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Ssl = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.SslCertificate = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.SslCertificateHost = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.SslCertificateValidation = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Username = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Warehouse = core.StringPtr("testString")

				// Construct an instance of the AddDatasourceConnectionOptions model
				addDatasourceConnectionOptionsModel := new(datavirtualizationv1.AddDatasourceConnectionOptions)
				addDatasourceConnectionOptionsModel.DatasourceType = core.StringPtr("testString")
				addDatasourceConnectionOptionsModel.Name = core.StringPtr("testString")
				addDatasourceConnectionOptionsModel.OriginCountry = core.StringPtr("testString")
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
	})

	Describe(`DeleteDatasourceConnection(deleteDatasourceConnectionOptions *DeleteDatasourceConnectionOptions)`, func() {
		deleteDatasourceConnectionPath := "/v2/datasource_connections"
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(deleteDatasourceConnectionPath))
					Expect(req.Method).To(Equal("DELETE"))

					Expect(req.URL.Query()["cid"]).To(Equal([]string{"DB210013"}))

					Expect(req.URL.Query()["connection_id"]).To(Equal([]string{"75e4d01b-7417-4abc-b267-8ffb393fb970"}))

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
				dataVirtualizationService.EnableRetries(0, 0)

				// Invoke operation with nil options model (negative test)
				response, operationErr := dataVirtualizationService.DeleteDatasourceConnection(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())

				// Construct an instance of the DeleteDatasourceConnectionOptions model
				deleteDatasourceConnectionOptionsModel := new(datavirtualizationv1.DeleteDatasourceConnectionOptions)
				deleteDatasourceConnectionOptionsModel.Cid = core.StringPtr("DB210013")
				deleteDatasourceConnectionOptionsModel.ConnectionID = core.StringPtr("75e4d01b-7417-4abc-b267-8ffb393fb970")
				deleteDatasourceConnectionOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				response, operationErr = dataVirtualizationService.DeleteDatasourceConnection(deleteDatasourceConnectionOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Disable retries and test again
				dataVirtualizationService.DisableRetries()
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
				deleteDatasourceConnectionOptionsModel.Cid = core.StringPtr("DB210013")
				deleteDatasourceConnectionOptionsModel.ConnectionID = core.StringPtr("75e4d01b-7417-4abc-b267-8ffb393fb970")
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
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
				})
				Expect(dataVirtualizationService).ToNot(BeNil())
				Expect(serviceErr).To(BeNil())
				ClearTestEnvironment(testEnvironment)
			})
			It(`Create service client using external config and set url from constructor successfully`, func() {
				SetTestEnvironment(testEnvironment)
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL: "https://testService/api",
				})
				Expect(dataVirtualizationService).ToNot(BeNil())
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService.Service.GetServiceURL()).To(Equal("https://testService/api"))
				ClearTestEnvironment(testEnvironment)
			})
			It(`Create service client using external config and set url programatically successfully`, func() {
				SetTestEnvironment(testEnvironment)
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
				})
				err := dataVirtualizationService.SetServiceURL("https://testService/api")
				Expect(err).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService.Service.GetServiceURL()).To(Equal("https://testService/api"))
				ClearTestEnvironment(testEnvironment)
			})
		})
		Context(`Using external config, construct service client instances with error: Invalid Auth`, func() {
			// Map containing environment variables used in testing.
			var testEnvironment = map[string]string{
				"DATA_VIRTUALIZATION_URL": "https://datavirtualizationv1/api",
				"DATA_VIRTUALIZATION_AUTH_TYPE": "someOtherAuth",
			}

			SetTestEnvironment(testEnvironment)
			dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
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
			dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
				URL: "{BAD_URL_STRING",
			})

			It(`Instantiate service client with error`, func() {
				Expect(dataVirtualizationService).To(BeNil())
				Expect(serviceErr).ToNot(BeNil())
				ClearTestEnvironment(testEnvironment)
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
				dataVirtualizationService.EnableRetries(0, 0)

				// Invoke operation with nil options model (negative test)
				response, operationErr := dataVirtualizationService.GrantUserToVirtualTable(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())

				// Construct an instance of the PostUserPrivilegesParametersBodyItem model
				postUserPrivilegesParametersBodyItemModel := new(datavirtualizationv1.PostUserPrivilegesParametersBodyItem)
				postUserPrivilegesParametersBodyItemModel.TableName = core.StringPtr("EMPLOYEE")
				postUserPrivilegesParametersBodyItemModel.TableSchema = core.StringPtr("USER999")
				postUserPrivilegesParametersBodyItemModel.Authid = core.StringPtr("PUBLIC")

				// Construct an instance of the GrantUserToVirtualTableOptions model
				grantUserToVirtualTableOptionsModel := new(datavirtualizationv1.GrantUserToVirtualTableOptions)
				grantUserToVirtualTableOptionsModel.Body = []datavirtualizationv1.PostUserPrivilegesParametersBodyItem{*postUserPrivilegesParametersBodyItemModel}
				grantUserToVirtualTableOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				response, operationErr = dataVirtualizationService.GrantUserToVirtualTable(grantUserToVirtualTableOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Disable retries and test again
				dataVirtualizationService.DisableRetries()
				response, operationErr = dataVirtualizationService.GrantUserToVirtualTable(grantUserToVirtualTableOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
			})
			It(`Invoke GrantUserToVirtualTable with error: Operation request error`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())

				// Construct an instance of the PostUserPrivilegesParametersBodyItem model
				postUserPrivilegesParametersBodyItemModel := new(datavirtualizationv1.PostUserPrivilegesParametersBodyItem)
				postUserPrivilegesParametersBodyItemModel.TableName = core.StringPtr("EMPLOYEE")
				postUserPrivilegesParametersBodyItemModel.TableSchema = core.StringPtr("USER999")
				postUserPrivilegesParametersBodyItemModel.Authid = core.StringPtr("PUBLIC")

				// Construct an instance of the GrantUserToVirtualTableOptions model
				grantUserToVirtualTableOptionsModel := new(datavirtualizationv1.GrantUserToVirtualTableOptions)
				grantUserToVirtualTableOptionsModel.Body = []datavirtualizationv1.PostUserPrivilegesParametersBodyItem{*postUserPrivilegesParametersBodyItemModel}
				grantUserToVirtualTableOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := dataVirtualizationService.SetServiceURL("")
				Expect(err).To(BeNil())
				response, operationErr := dataVirtualizationService.GrantUserToVirtualTable(grantUserToVirtualTableOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})

	Describe(`RevokeUserFromObject(revokeUserFromObjectOptions *RevokeUserFromObjectOptions)`, func() {
		revokeUserFromObjectPath := "/v2/privileges/users"
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(revokeUserFromObjectPath))
					Expect(req.Method).To(Equal("DELETE"))

					Expect(req.URL.Query()["authid"]).To(Equal([]string{"PUBLIC"}))

					Expect(req.URL.Query()["table_name"]).To(Equal([]string{"EMPLOYEE"}))

					Expect(req.URL.Query()["table_schema"]).To(Equal([]string{"USER999"}))

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
				dataVirtualizationService.EnableRetries(0, 0)

				// Invoke operation with nil options model (negative test)
				response, operationErr := dataVirtualizationService.RevokeUserFromObject(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())

				// Construct an instance of the RevokeUserFromObjectOptions model
				revokeUserFromObjectOptionsModel := new(datavirtualizationv1.RevokeUserFromObjectOptions)
				revokeUserFromObjectOptionsModel.Authid = core.StringPtr("PUBLIC")
				revokeUserFromObjectOptionsModel.TableName = core.StringPtr("EMPLOYEE")
				revokeUserFromObjectOptionsModel.TableSchema = core.StringPtr("USER999")
				revokeUserFromObjectOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				response, operationErr = dataVirtualizationService.RevokeUserFromObject(revokeUserFromObjectOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Disable retries and test again
				dataVirtualizationService.DisableRetries()
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
				revokeUserFromObjectOptionsModel.TableSchema = core.StringPtr("USER999")
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
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
				})
				Expect(dataVirtualizationService).ToNot(BeNil())
				Expect(serviceErr).To(BeNil())
				ClearTestEnvironment(testEnvironment)
			})
			It(`Create service client using external config and set url from constructor successfully`, func() {
				SetTestEnvironment(testEnvironment)
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL: "https://testService/api",
				})
				Expect(dataVirtualizationService).ToNot(BeNil())
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService.Service.GetServiceURL()).To(Equal("https://testService/api"))
				ClearTestEnvironment(testEnvironment)
			})
			It(`Create service client using external config and set url programatically successfully`, func() {
				SetTestEnvironment(testEnvironment)
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
				})
				err := dataVirtualizationService.SetServiceURL("https://testService/api")
				Expect(err).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService.Service.GetServiceURL()).To(Equal("https://testService/api"))
				ClearTestEnvironment(testEnvironment)
			})
		})
		Context(`Using external config, construct service client instances with error: Invalid Auth`, func() {
			// Map containing environment variables used in testing.
			var testEnvironment = map[string]string{
				"DATA_VIRTUALIZATION_URL": "https://datavirtualizationv1/api",
				"DATA_VIRTUALIZATION_AUTH_TYPE": "someOtherAuth",
			}

			SetTestEnvironment(testEnvironment)
			dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
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
			dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
				URL: "{BAD_URL_STRING",
			})

			It(`Instantiate service client with error`, func() {
				Expect(dataVirtualizationService).To(BeNil())
				Expect(serviceErr).ToNot(BeNil())
				ClearTestEnvironment(testEnvironment)
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
				dataVirtualizationService.EnableRetries(0, 0)

				// Invoke operation with nil options model (negative test)
				response, operationErr := dataVirtualizationService.GrantRolesToVirtualizedTable(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())

				// Construct an instance of the PostRolePrivilegesParametersBodyItem model
				postRolePrivilegesParametersBodyItemModel := new(datavirtualizationv1.PostRolePrivilegesParametersBodyItem)
				postRolePrivilegesParametersBodyItemModel.TableName = core.StringPtr("EMPLOYEE")
				postRolePrivilegesParametersBodyItemModel.TableSchema = core.StringPtr("USER999")
				postRolePrivilegesParametersBodyItemModel.RoleToGrant = core.StringPtr("PUBLIC")

				// Construct an instance of the GrantRolesToVirtualizedTableOptions model
				grantRolesToVirtualizedTableOptionsModel := new(datavirtualizationv1.GrantRolesToVirtualizedTableOptions)
				grantRolesToVirtualizedTableOptionsModel.Body = []datavirtualizationv1.PostRolePrivilegesParametersBodyItem{*postRolePrivilegesParametersBodyItemModel}
				grantRolesToVirtualizedTableOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				response, operationErr = dataVirtualizationService.GrantRolesToVirtualizedTable(grantRolesToVirtualizedTableOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Disable retries and test again
				dataVirtualizationService.DisableRetries()
				response, operationErr = dataVirtualizationService.GrantRolesToVirtualizedTable(grantRolesToVirtualizedTableOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
			})
			It(`Invoke GrantRolesToVirtualizedTable with error: Operation request error`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())

				// Construct an instance of the PostRolePrivilegesParametersBodyItem model
				postRolePrivilegesParametersBodyItemModel := new(datavirtualizationv1.PostRolePrivilegesParametersBodyItem)
				postRolePrivilegesParametersBodyItemModel.TableName = core.StringPtr("EMPLOYEE")
				postRolePrivilegesParametersBodyItemModel.TableSchema = core.StringPtr("USER999")
				postRolePrivilegesParametersBodyItemModel.RoleToGrant = core.StringPtr("PUBLIC")

				// Construct an instance of the GrantRolesToVirtualizedTableOptions model
				grantRolesToVirtualizedTableOptionsModel := new(datavirtualizationv1.GrantRolesToVirtualizedTableOptions)
				grantRolesToVirtualizedTableOptionsModel.Body = []datavirtualizationv1.PostRolePrivilegesParametersBodyItem{*postRolePrivilegesParametersBodyItemModel}
				grantRolesToVirtualizedTableOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := dataVirtualizationService.SetServiceURL("")
				Expect(err).To(BeNil())
				response, operationErr := dataVirtualizationService.GrantRolesToVirtualizedTable(grantRolesToVirtualizedTableOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})

	Describe(`RevokeRoleFromTableV2(revokeRoleFromTableV2Options *RevokeRoleFromTableV2Options)`, func() {
		revokeRoleFromTableV2Path := "/v2/privileges/roles"
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(revokeRoleFromTableV2Path))
					Expect(req.Method).To(Equal("DELETE"))

					Expect(req.URL.Query()["role_to_revoke"]).To(Equal([]string{"DV_ENGINEER"}))

					Expect(req.URL.Query()["table_name"]).To(Equal([]string{"EMPLOYEE"}))

					Expect(req.URL.Query()["table_schema"]).To(Equal([]string{"USER999"}))

					res.WriteHeader(204)
				}))
			})
			It(`Invoke RevokeRoleFromTableV2 successfully`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())
				dataVirtualizationService.EnableRetries(0, 0)

				// Invoke operation with nil options model (negative test)
				response, operationErr := dataVirtualizationService.RevokeRoleFromTableV2(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())

				// Construct an instance of the RevokeRoleFromTableV2Options model
				revokeRoleFromTableV2OptionsModel := new(datavirtualizationv1.RevokeRoleFromTableV2Options)
				revokeRoleFromTableV2OptionsModel.RoleToRevoke = core.StringPtr("DV_ENGINEER")
				revokeRoleFromTableV2OptionsModel.TableName = core.StringPtr("EMPLOYEE")
				revokeRoleFromTableV2OptionsModel.TableSchema = core.StringPtr("USER999")
				revokeRoleFromTableV2OptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				response, operationErr = dataVirtualizationService.RevokeRoleFromTableV2(revokeRoleFromTableV2OptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Disable retries and test again
				dataVirtualizationService.DisableRetries()
				response, operationErr = dataVirtualizationService.RevokeRoleFromTableV2(revokeRoleFromTableV2OptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
			})
			It(`Invoke RevokeRoleFromTableV2 with error: Operation validation and request error`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())

				// Construct an instance of the RevokeRoleFromTableV2Options model
				revokeRoleFromTableV2OptionsModel := new(datavirtualizationv1.RevokeRoleFromTableV2Options)
				revokeRoleFromTableV2OptionsModel.RoleToRevoke = core.StringPtr("DV_ENGINEER")
				revokeRoleFromTableV2OptionsModel.TableName = core.StringPtr("EMPLOYEE")
				revokeRoleFromTableV2OptionsModel.TableSchema = core.StringPtr("USER999")
				revokeRoleFromTableV2OptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := dataVirtualizationService.SetServiceURL("")
				Expect(err).To(BeNil())
				response, operationErr := dataVirtualizationService.RevokeRoleFromTableV2(revokeRoleFromTableV2OptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				// Construct a second instance of the RevokeRoleFromTableV2Options model with no property values
				revokeRoleFromTableV2OptionsModelNew := new(datavirtualizationv1.RevokeRoleFromTableV2Options)
				// Invoke operation with invalid model (negative test)
				response, operationErr = dataVirtualizationService.RevokeRoleFromTableV2(revokeRoleFromTableV2OptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetTablesForRole(getTablesForRoleOptions *GetTablesForRoleOptions) - Operation response error`, func() {
		getTablesForRolePath := "/v2/privileges/tables/role/ADMIN%20%7C%20STEWARD%20%7C%20ENGINEER%20%7C%20USER"
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getTablesForRolePath))
					Expect(req.Method).To(Equal("GET"))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke GetTablesForRole with error: Operation response processing error`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())

				// Construct an instance of the GetTablesForRoleOptions model
				getTablesForRoleOptionsModel := new(datavirtualizationv1.GetTablesForRoleOptions)
				getTablesForRoleOptionsModel.Rolename = core.StringPtr("ADMIN | STEWARD | ENGINEER | USER")
				getTablesForRoleOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := dataVirtualizationService.GetTablesForRole(getTablesForRoleOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				dataVirtualizationService.EnableRetries(0, 0)
				result, response, operationErr = dataVirtualizationService.GetTablesForRole(getTablesForRoleOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})

	Describe(`GetTablesForRole(getTablesForRoleOptions *GetTablesForRoleOptions)`, func() {
		getTablesForRolePath := "/v2/privileges/tables/role/ADMIN%20%7C%20STEWARD%20%7C%20ENGINEER%20%7C%20USER"
		var serverSleepTime time.Duration
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				serverSleepTime = 0
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getTablesForRolePath))
					Expect(req.Method).To(Equal("GET"))

					// Sleep a short time to support a timeout test
					time.Sleep(serverSleepTime)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"objects": [{"table_name": "TableName", "table_schema": "TableSchema"}]}`)
				}))
			})
			It(`Invoke GetTablesForRole successfully`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())
				dataVirtualizationService.EnableRetries(0, 0)

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := dataVirtualizationService.GetTablesForRole(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the GetTablesForRoleOptions model
				getTablesForRoleOptionsModel := new(datavirtualizationv1.GetTablesForRoleOptions)
				getTablesForRoleOptionsModel.Rolename = core.StringPtr("ADMIN | STEWARD | ENGINEER | USER")
				getTablesForRoleOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = dataVirtualizationService.GetTablesForRole(getTablesForRoleOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				serverSleepTime = 100 * time.Millisecond
				_, _, operationErr = dataVirtualizationService.GetTablesForRoleWithContext(ctx, getTablesForRoleOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
				serverSleepTime = time.Duration(0)

				// Disable retries and test again
				dataVirtualizationService.DisableRetries()
				result, response, operationErr = dataVirtualizationService.GetTablesForRole(getTablesForRoleOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				serverSleepTime = 100 * time.Millisecond
				_, _, operationErr = dataVirtualizationService.GetTablesForRoleWithContext(ctx, getTablesForRoleOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
				serverSleepTime = time.Duration(0)
			})
			It(`Invoke GetTablesForRole with error: Operation validation and request error`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())

				// Construct an instance of the GetTablesForRoleOptions model
				getTablesForRoleOptionsModel := new(datavirtualizationv1.GetTablesForRoleOptions)
				getTablesForRoleOptionsModel.Rolename = core.StringPtr("ADMIN | STEWARD | ENGINEER | USER")
				getTablesForRoleOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := dataVirtualizationService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := dataVirtualizationService.GetTablesForRole(getTablesForRoleOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the GetTablesForRoleOptions model with no property values
				getTablesForRoleOptionsModelNew := new(datavirtualizationv1.GetTablesForRoleOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = dataVirtualizationService.GetTablesForRole(getTablesForRoleOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
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
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
				})
				Expect(dataVirtualizationService).ToNot(BeNil())
				Expect(serviceErr).To(BeNil())
				ClearTestEnvironment(testEnvironment)
			})
			It(`Create service client using external config and set url from constructor successfully`, func() {
				SetTestEnvironment(testEnvironment)
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL: "https://testService/api",
				})
				Expect(dataVirtualizationService).ToNot(BeNil())
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService.Service.GetServiceURL()).To(Equal("https://testService/api"))
				ClearTestEnvironment(testEnvironment)
			})
			It(`Create service client using external config and set url programatically successfully`, func() {
				SetTestEnvironment(testEnvironment)
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
				})
				err := dataVirtualizationService.SetServiceURL("https://testService/api")
				Expect(err).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService.Service.GetServiceURL()).To(Equal("https://testService/api"))
				ClearTestEnvironment(testEnvironment)
			})
		})
		Context(`Using external config, construct service client instances with error: Invalid Auth`, func() {
			// Map containing environment variables used in testing.
			var testEnvironment = map[string]string{
				"DATA_VIRTUALIZATION_URL": "https://datavirtualizationv1/api",
				"DATA_VIRTUALIZATION_AUTH_TYPE": "someOtherAuth",
			}

			SetTestEnvironment(testEnvironment)
			dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
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
			dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
				URL: "{BAD_URL_STRING",
			})

			It(`Instantiate service client with error`, func() {
				Expect(dataVirtualizationService).To(BeNil())
				Expect(serviceErr).ToNot(BeNil())
				ClearTestEnvironment(testEnvironment)
			})
		})
	})
	Describe(`VirtualizeTableV2(virtualizeTableV2Options *VirtualizeTableV2Options) - Operation response error`, func() {
		virtualizeTableV2Path := "/v2/virtualize/tables"
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(virtualizeTableV2Path))
					Expect(req.Method).To(Equal("POST"))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(201)
					fmt.Fprintf(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke VirtualizeTableV2 with error: Operation response processing error`, func() {
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

				// Construct an instance of the VirtualizeTableV2Options model
				virtualizeTableV2OptionsModel := new(datavirtualizationv1.VirtualizeTableV2Options)
				virtualizeTableV2OptionsModel.SourceName = core.StringPtr("Tab1")
				virtualizeTableV2OptionsModel.SourceTableDef = []datavirtualizationv1.VirtualizeTableParameterSourceTableDefItem{*virtualizeTableParameterSourceTableDefItemModel}
				virtualizeTableV2OptionsModel.Sources = []string{`DB210001:"Hjq1"`}
				virtualizeTableV2OptionsModel.VirtualName = core.StringPtr("Tab1")
				virtualizeTableV2OptionsModel.VirtualSchema = core.StringPtr("USER999")
				virtualizeTableV2OptionsModel.VirtualTableDef = []datavirtualizationv1.VirtualizeTableParameterVirtualTableDefItem{*virtualizeTableParameterVirtualTableDefItemModel}
				virtualizeTableV2OptionsModel.IsIncludedColumns = core.StringPtr("Y, Y, N")
				virtualizeTableV2OptionsModel.Replace = core.BoolPtr(false)
				virtualizeTableV2OptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := dataVirtualizationService.VirtualizeTableV2(virtualizeTableV2OptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				dataVirtualizationService.EnableRetries(0, 0)
				result, response, operationErr = dataVirtualizationService.VirtualizeTableV2(virtualizeTableV2OptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})

	Describe(`VirtualizeTableV2(virtualizeTableV2Options *VirtualizeTableV2Options)`, func() {
		virtualizeTableV2Path := "/v2/virtualize/tables"
		var serverSleepTime time.Duration
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				serverSleepTime = 0
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(virtualizeTableV2Path))
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
					time.Sleep(serverSleepTime)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(201)
					fmt.Fprintf(res, "%s", `{"source_name": "Tab1", "virtual_name": "Tab1", "virtual_schema": "USER999"}`)
				}))
			})
			It(`Invoke VirtualizeTableV2 successfully`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())
				dataVirtualizationService.EnableRetries(0, 0)

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := dataVirtualizationService.VirtualizeTableV2(nil)
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

				// Construct an instance of the VirtualizeTableV2Options model
				virtualizeTableV2OptionsModel := new(datavirtualizationv1.VirtualizeTableV2Options)
				virtualizeTableV2OptionsModel.SourceName = core.StringPtr("Tab1")
				virtualizeTableV2OptionsModel.SourceTableDef = []datavirtualizationv1.VirtualizeTableParameterSourceTableDefItem{*virtualizeTableParameterSourceTableDefItemModel}
				virtualizeTableV2OptionsModel.Sources = []string{`DB210001:"Hjq1"`}
				virtualizeTableV2OptionsModel.VirtualName = core.StringPtr("Tab1")
				virtualizeTableV2OptionsModel.VirtualSchema = core.StringPtr("USER999")
				virtualizeTableV2OptionsModel.VirtualTableDef = []datavirtualizationv1.VirtualizeTableParameterVirtualTableDefItem{*virtualizeTableParameterVirtualTableDefItemModel}
				virtualizeTableV2OptionsModel.IsIncludedColumns = core.StringPtr("Y, Y, N")
				virtualizeTableV2OptionsModel.Replace = core.BoolPtr(false)
				virtualizeTableV2OptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = dataVirtualizationService.VirtualizeTableV2(virtualizeTableV2OptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				serverSleepTime = 100 * time.Millisecond
				_, _, operationErr = dataVirtualizationService.VirtualizeTableV2WithContext(ctx, virtualizeTableV2OptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
				serverSleepTime = time.Duration(0)

				// Disable retries and test again
				dataVirtualizationService.DisableRetries()
				result, response, operationErr = dataVirtualizationService.VirtualizeTableV2(virtualizeTableV2OptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				serverSleepTime = 100 * time.Millisecond
				_, _, operationErr = dataVirtualizationService.VirtualizeTableV2WithContext(ctx, virtualizeTableV2OptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
				serverSleepTime = time.Duration(0)
			})
			It(`Invoke VirtualizeTableV2 with error: Operation validation and request error`, func() {
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

				// Construct an instance of the VirtualizeTableV2Options model
				virtualizeTableV2OptionsModel := new(datavirtualizationv1.VirtualizeTableV2Options)
				virtualizeTableV2OptionsModel.SourceName = core.StringPtr("Tab1")
				virtualizeTableV2OptionsModel.SourceTableDef = []datavirtualizationv1.VirtualizeTableParameterSourceTableDefItem{*virtualizeTableParameterSourceTableDefItemModel}
				virtualizeTableV2OptionsModel.Sources = []string{`DB210001:"Hjq1"`}
				virtualizeTableV2OptionsModel.VirtualName = core.StringPtr("Tab1")
				virtualizeTableV2OptionsModel.VirtualSchema = core.StringPtr("USER999")
				virtualizeTableV2OptionsModel.VirtualTableDef = []datavirtualizationv1.VirtualizeTableParameterVirtualTableDefItem{*virtualizeTableParameterVirtualTableDefItemModel}
				virtualizeTableV2OptionsModel.IsIncludedColumns = core.StringPtr("Y, Y, N")
				virtualizeTableV2OptionsModel.Replace = core.BoolPtr(false)
				virtualizeTableV2OptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := dataVirtualizationService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := dataVirtualizationService.VirtualizeTableV2(virtualizeTableV2OptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the VirtualizeTableV2Options model with no property values
				virtualizeTableV2OptionsModelNew := new(datavirtualizationv1.VirtualizeTableV2Options)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = dataVirtualizationService.VirtualizeTableV2(virtualizeTableV2OptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
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
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
				})
				Expect(dataVirtualizationService).ToNot(BeNil())
				Expect(serviceErr).To(BeNil())
				ClearTestEnvironment(testEnvironment)
			})
			It(`Create service client using external config and set url from constructor successfully`, func() {
				SetTestEnvironment(testEnvironment)
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL: "https://testService/api",
				})
				Expect(dataVirtualizationService).ToNot(BeNil())
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService.Service.GetServiceURL()).To(Equal("https://testService/api"))
				ClearTestEnvironment(testEnvironment)
			})
			It(`Create service client using external config and set url programatically successfully`, func() {
				SetTestEnvironment(testEnvironment)
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
				})
				err := dataVirtualizationService.SetServiceURL("https://testService/api")
				Expect(err).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService.Service.GetServiceURL()).To(Equal("https://testService/api"))
				ClearTestEnvironment(testEnvironment)
			})
		})
		Context(`Using external config, construct service client instances with error: Invalid Auth`, func() {
			// Map containing environment variables used in testing.
			var testEnvironment = map[string]string{
				"DATA_VIRTUALIZATION_URL": "https://datavirtualizationv1/api",
				"DATA_VIRTUALIZATION_AUTH_TYPE": "someOtherAuth",
			}

			SetTestEnvironment(testEnvironment)
			dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
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
			dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
				URL: "{BAD_URL_STRING",
			})

			It(`Instantiate service client with error`, func() {
				Expect(dataVirtualizationService).To(BeNil())
				Expect(serviceErr).ToNot(BeNil())
				ClearTestEnvironment(testEnvironment)
			})
		})
	})

	Describe(`DeleteTable(deleteTableOptions *DeleteTableOptions)`, func() {
		deleteTablePath := "/v2/mydata/tables/testString"
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(deleteTablePath))
					Expect(req.Method).To(Equal("DELETE"))

					Expect(req.URL.Query()["schema_name"]).To(Equal([]string{"testString"}))

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
				dataVirtualizationService.EnableRetries(0, 0)

				// Invoke operation with nil options model (negative test)
				response, operationErr := dataVirtualizationService.DeleteTable(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())

				// Construct an instance of the DeleteTableOptions model
				deleteTableOptionsModel := new(datavirtualizationv1.DeleteTableOptions)
				deleteTableOptionsModel.SchemaName = core.StringPtr("testString")
				deleteTableOptionsModel.TableName = core.StringPtr("testString")
				deleteTableOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				response, operationErr = dataVirtualizationService.DeleteTable(deleteTableOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Disable retries and test again
				dataVirtualizationService.DisableRetries()
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
				deleteTableOptionsModel.SchemaName = core.StringPtr("testString")
				deleteTableOptionsModel.TableName = core.StringPtr("testString")
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
				postDatasourceConnectionParametersPropertiesModel.ApiKey = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.AuthType = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.ClientID = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.ClientSecret = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Collection = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Credentials = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Database = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Host = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.HttpPath = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.JarUris = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.JdbcDriver = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.JdbcURL = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Password = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Port = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.ProjectID = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Properties = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.RefreshToken = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Role = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.SapGatewayURL = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Server = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.ServiceName = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Sid = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Ssl = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.SslCertificate = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.SslCertificateHost = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.SslCertificateValidation = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Username = core.StringPtr("testString")
				postDatasourceConnectionParametersPropertiesModel.Warehouse = core.StringPtr("testString")
				Expect(postDatasourceConnectionParametersPropertiesModel.AccessToken).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersPropertiesModel.AccountName).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersPropertiesModel.ApiKey).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersPropertiesModel.AuthType).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersPropertiesModel.ClientID).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersPropertiesModel.ClientSecret).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersPropertiesModel.Collection).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersPropertiesModel.Credentials).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersPropertiesModel.Database).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersPropertiesModel.Host).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersPropertiesModel.HttpPath).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersPropertiesModel.JarUris).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersPropertiesModel.JdbcDriver).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersPropertiesModel.JdbcURL).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersPropertiesModel.Password).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersPropertiesModel.Port).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersPropertiesModel.ProjectID).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersPropertiesModel.Properties).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersPropertiesModel.RefreshToken).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersPropertiesModel.Role).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersPropertiesModel.SapGatewayURL).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersPropertiesModel.Server).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersPropertiesModel.ServiceName).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersPropertiesModel.Sid).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersPropertiesModel.Ssl).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersPropertiesModel.SslCertificate).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersPropertiesModel.SslCertificateHost).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersPropertiesModel.SslCertificateValidation).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersPropertiesModel.Username).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersPropertiesModel.Warehouse).To(Equal(core.StringPtr("testString")))

				// Construct an instance of the AddDatasourceConnectionOptions model
				addDatasourceConnectionOptionsDatasourceType := "testString"
				addDatasourceConnectionOptionsName := "testString"
				addDatasourceConnectionOptionsOriginCountry := "testString"
				var addDatasourceConnectionOptionsProperties *datavirtualizationv1.PostDatasourceConnectionParametersProperties = nil
				addDatasourceConnectionOptionsModel := dataVirtualizationService.NewAddDatasourceConnectionOptions(addDatasourceConnectionOptionsDatasourceType, addDatasourceConnectionOptionsName, addDatasourceConnectionOptionsOriginCountry, addDatasourceConnectionOptionsProperties)
				addDatasourceConnectionOptionsModel.SetDatasourceType("testString")
				addDatasourceConnectionOptionsModel.SetName("testString")
				addDatasourceConnectionOptionsModel.SetOriginCountry("testString")
				addDatasourceConnectionOptionsModel.SetProperties(postDatasourceConnectionParametersPropertiesModel)
				addDatasourceConnectionOptionsModel.SetAssetCategory("testString")
				addDatasourceConnectionOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(addDatasourceConnectionOptionsModel).ToNot(BeNil())
				Expect(addDatasourceConnectionOptionsModel.DatasourceType).To(Equal(core.StringPtr("testString")))
				Expect(addDatasourceConnectionOptionsModel.Name).To(Equal(core.StringPtr("testString")))
				Expect(addDatasourceConnectionOptionsModel.OriginCountry).To(Equal(core.StringPtr("testString")))
				Expect(addDatasourceConnectionOptionsModel.Properties).To(Equal(postDatasourceConnectionParametersPropertiesModel))
				Expect(addDatasourceConnectionOptionsModel.AssetCategory).To(Equal(core.StringPtr("testString")))
				Expect(addDatasourceConnectionOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewDeleteDatasourceConnectionOptions successfully`, func() {
				// Construct an instance of the DeleteDatasourceConnectionOptions model
				cid := "DB210013"
				connectionID := "75e4d01b-7417-4abc-b267-8ffb393fb970"
				deleteDatasourceConnectionOptionsModel := dataVirtualizationService.NewDeleteDatasourceConnectionOptions(cid, connectionID)
				deleteDatasourceConnectionOptionsModel.SetCid("DB210013")
				deleteDatasourceConnectionOptionsModel.SetConnectionID("75e4d01b-7417-4abc-b267-8ffb393fb970")
				deleteDatasourceConnectionOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(deleteDatasourceConnectionOptionsModel).ToNot(BeNil())
				Expect(deleteDatasourceConnectionOptionsModel.Cid).To(Equal(core.StringPtr("DB210013")))
				Expect(deleteDatasourceConnectionOptionsModel.ConnectionID).To(Equal(core.StringPtr("75e4d01b-7417-4abc-b267-8ffb393fb970")))
				Expect(deleteDatasourceConnectionOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewDeleteTableOptions successfully`, func() {
				// Construct an instance of the DeleteTableOptions model
				schemaName := "testString"
				tableName := "testString"
				deleteTableOptionsModel := dataVirtualizationService.NewDeleteTableOptions(schemaName, tableName)
				deleteTableOptionsModel.SetSchemaName("testString")
				deleteTableOptionsModel.SetTableName("testString")
				deleteTableOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(deleteTableOptionsModel).ToNot(BeNil())
				Expect(deleteTableOptionsModel.SchemaName).To(Equal(core.StringPtr("testString")))
				Expect(deleteTableOptionsModel.TableName).To(Equal(core.StringPtr("testString")))
				Expect(deleteTableOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewGetDatasourceConnectionsOptions successfully`, func() {
				// Construct an instance of the GetDatasourceConnectionsOptions model
				getDatasourceConnectionsOptionsModel := dataVirtualizationService.NewGetDatasourceConnectionsOptions()
				getDatasourceConnectionsOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(getDatasourceConnectionsOptionsModel).ToNot(BeNil())
				Expect(getDatasourceConnectionsOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewGetTablesForRoleOptions successfully`, func() {
				// Construct an instance of the GetTablesForRoleOptions model
				rolename := "ADMIN | STEWARD | ENGINEER | USER"
				getTablesForRoleOptionsModel := dataVirtualizationService.NewGetTablesForRoleOptions(rolename)
				getTablesForRoleOptionsModel.SetRolename("ADMIN | STEWARD | ENGINEER | USER")
				getTablesForRoleOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(getTablesForRoleOptionsModel).ToNot(BeNil())
				Expect(getTablesForRoleOptionsModel.Rolename).To(Equal(core.StringPtr("ADMIN | STEWARD | ENGINEER | USER")))
				Expect(getTablesForRoleOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewGrantRolesToVirtualizedTableOptions successfully`, func() {
				// Construct an instance of the PostRolePrivilegesParametersBodyItem model
				postRolePrivilegesParametersBodyItemModel := new(datavirtualizationv1.PostRolePrivilegesParametersBodyItem)
				Expect(postRolePrivilegesParametersBodyItemModel).ToNot(BeNil())
				postRolePrivilegesParametersBodyItemModel.TableName = core.StringPtr("EMPLOYEE")
				postRolePrivilegesParametersBodyItemModel.TableSchema = core.StringPtr("USER999")
				postRolePrivilegesParametersBodyItemModel.RoleToGrant = core.StringPtr("PUBLIC")
				Expect(postRolePrivilegesParametersBodyItemModel.TableName).To(Equal(core.StringPtr("EMPLOYEE")))
				Expect(postRolePrivilegesParametersBodyItemModel.TableSchema).To(Equal(core.StringPtr("USER999")))
				Expect(postRolePrivilegesParametersBodyItemModel.RoleToGrant).To(Equal(core.StringPtr("PUBLIC")))

				// Construct an instance of the GrantRolesToVirtualizedTableOptions model
				grantRolesToVirtualizedTableOptionsModel := dataVirtualizationService.NewGrantRolesToVirtualizedTableOptions()
				grantRolesToVirtualizedTableOptionsModel.SetBody([]datavirtualizationv1.PostRolePrivilegesParametersBodyItem{*postRolePrivilegesParametersBodyItemModel})
				grantRolesToVirtualizedTableOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(grantRolesToVirtualizedTableOptionsModel).ToNot(BeNil())
				Expect(grantRolesToVirtualizedTableOptionsModel.Body).To(Equal([]datavirtualizationv1.PostRolePrivilegesParametersBodyItem{*postRolePrivilegesParametersBodyItemModel}))
				Expect(grantRolesToVirtualizedTableOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewGrantUserToVirtualTableOptions successfully`, func() {
				// Construct an instance of the PostUserPrivilegesParametersBodyItem model
				postUserPrivilegesParametersBodyItemModel := new(datavirtualizationv1.PostUserPrivilegesParametersBodyItem)
				Expect(postUserPrivilegesParametersBodyItemModel).ToNot(BeNil())
				postUserPrivilegesParametersBodyItemModel.TableName = core.StringPtr("EMPLOYEE")
				postUserPrivilegesParametersBodyItemModel.TableSchema = core.StringPtr("USER999")
				postUserPrivilegesParametersBodyItemModel.Authid = core.StringPtr("PUBLIC")
				Expect(postUserPrivilegesParametersBodyItemModel.TableName).To(Equal(core.StringPtr("EMPLOYEE")))
				Expect(postUserPrivilegesParametersBodyItemModel.TableSchema).To(Equal(core.StringPtr("USER999")))
				Expect(postUserPrivilegesParametersBodyItemModel.Authid).To(Equal(core.StringPtr("PUBLIC")))

				// Construct an instance of the GrantUserToVirtualTableOptions model
				grantUserToVirtualTableOptionsModel := dataVirtualizationService.NewGrantUserToVirtualTableOptions()
				grantUserToVirtualTableOptionsModel.SetBody([]datavirtualizationv1.PostUserPrivilegesParametersBodyItem{*postUserPrivilegesParametersBodyItemModel})
				grantUserToVirtualTableOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(grantUserToVirtualTableOptionsModel).ToNot(BeNil())
				Expect(grantUserToVirtualTableOptionsModel.Body).To(Equal([]datavirtualizationv1.PostUserPrivilegesParametersBodyItem{*postUserPrivilegesParametersBodyItemModel}))
				Expect(grantUserToVirtualTableOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewRevokeRoleFromTableV2Options successfully`, func() {
				// Construct an instance of the RevokeRoleFromTableV2Options model
				roleToRevoke := "DV_ENGINEER"
				tableName := "EMPLOYEE"
				tableSchema := "USER999"
				revokeRoleFromTableV2OptionsModel := dataVirtualizationService.NewRevokeRoleFromTableV2Options(roleToRevoke, tableName, tableSchema)
				revokeRoleFromTableV2OptionsModel.SetRoleToRevoke("DV_ENGINEER")
				revokeRoleFromTableV2OptionsModel.SetTableName("EMPLOYEE")
				revokeRoleFromTableV2OptionsModel.SetTableSchema("USER999")
				revokeRoleFromTableV2OptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(revokeRoleFromTableV2OptionsModel).ToNot(BeNil())
				Expect(revokeRoleFromTableV2OptionsModel.RoleToRevoke).To(Equal(core.StringPtr("DV_ENGINEER")))
				Expect(revokeRoleFromTableV2OptionsModel.TableName).To(Equal(core.StringPtr("EMPLOYEE")))
				Expect(revokeRoleFromTableV2OptionsModel.TableSchema).To(Equal(core.StringPtr("USER999")))
				Expect(revokeRoleFromTableV2OptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewRevokeUserFromObjectOptions successfully`, func() {
				// Construct an instance of the RevokeUserFromObjectOptions model
				authid := "PUBLIC"
				tableName := "EMPLOYEE"
				tableSchema := "USER999"
				revokeUserFromObjectOptionsModel := dataVirtualizationService.NewRevokeUserFromObjectOptions(authid, tableName, tableSchema)
				revokeUserFromObjectOptionsModel.SetAuthid("PUBLIC")
				revokeUserFromObjectOptionsModel.SetTableName("EMPLOYEE")
				revokeUserFromObjectOptionsModel.SetTableSchema("USER999")
				revokeUserFromObjectOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(revokeUserFromObjectOptionsModel).ToNot(BeNil())
				Expect(revokeUserFromObjectOptionsModel.Authid).To(Equal(core.StringPtr("PUBLIC")))
				Expect(revokeUserFromObjectOptionsModel.TableName).To(Equal(core.StringPtr("EMPLOYEE")))
				Expect(revokeUserFromObjectOptionsModel.TableSchema).To(Equal(core.StringPtr("USER999")))
				Expect(revokeUserFromObjectOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewVirtualizeTableParameterSourceTableDefItem successfully`, func() {
				columnName := "Column1"
				columnType := "INTEGER"
				model, err := dataVirtualizationService.NewVirtualizeTableParameterSourceTableDefItem(columnName, columnType)
				Expect(model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewVirtualizeTableParameterVirtualTableDefItem successfully`, func() {
				columnName := "Column_1"
				columnType := "INTEGER"
				model, err := dataVirtualizationService.NewVirtualizeTableParameterVirtualTableDefItem(columnName, columnType)
				Expect(model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewVirtualizeTableV2Options successfully`, func() {
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

				// Construct an instance of the VirtualizeTableV2Options model
				virtualizeTableV2OptionsSourceName := "Tab1"
				virtualizeTableV2OptionsSourceTableDef := []datavirtualizationv1.VirtualizeTableParameterSourceTableDefItem{}
				virtualizeTableV2OptionsSources := []string{`DB210001:"Hjq1"`}
				virtualizeTableV2OptionsVirtualName := "Tab1"
				virtualizeTableV2OptionsVirtualSchema := "USER999"
				virtualizeTableV2OptionsVirtualTableDef := []datavirtualizationv1.VirtualizeTableParameterVirtualTableDefItem{}
				virtualizeTableV2OptionsModel := dataVirtualizationService.NewVirtualizeTableV2Options(virtualizeTableV2OptionsSourceName, virtualizeTableV2OptionsSourceTableDef, virtualizeTableV2OptionsSources, virtualizeTableV2OptionsVirtualName, virtualizeTableV2OptionsVirtualSchema, virtualizeTableV2OptionsVirtualTableDef)
				virtualizeTableV2OptionsModel.SetSourceName("Tab1")
				virtualizeTableV2OptionsModel.SetSourceTableDef([]datavirtualizationv1.VirtualizeTableParameterSourceTableDefItem{*virtualizeTableParameterSourceTableDefItemModel})
				virtualizeTableV2OptionsModel.SetSources([]string{`DB210001:"Hjq1"`})
				virtualizeTableV2OptionsModel.SetVirtualName("Tab1")
				virtualizeTableV2OptionsModel.SetVirtualSchema("USER999")
				virtualizeTableV2OptionsModel.SetVirtualTableDef([]datavirtualizationv1.VirtualizeTableParameterVirtualTableDefItem{*virtualizeTableParameterVirtualTableDefItemModel})
				virtualizeTableV2OptionsModel.SetIsIncludedColumns("Y, Y, N")
				virtualizeTableV2OptionsModel.SetReplace(false)
				virtualizeTableV2OptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(virtualizeTableV2OptionsModel).ToNot(BeNil())
				Expect(virtualizeTableV2OptionsModel.SourceName).To(Equal(core.StringPtr("Tab1")))
				Expect(virtualizeTableV2OptionsModel.SourceTableDef).To(Equal([]datavirtualizationv1.VirtualizeTableParameterSourceTableDefItem{*virtualizeTableParameterSourceTableDefItemModel}))
				Expect(virtualizeTableV2OptionsModel.Sources).To(Equal([]string{`DB210001:"Hjq1"`}))
				Expect(virtualizeTableV2OptionsModel.VirtualName).To(Equal(core.StringPtr("Tab1")))
				Expect(virtualizeTableV2OptionsModel.VirtualSchema).To(Equal(core.StringPtr("USER999")))
				Expect(virtualizeTableV2OptionsModel.VirtualTableDef).To(Equal([]datavirtualizationv1.VirtualizeTableParameterVirtualTableDefItem{*virtualizeTableParameterVirtualTableDefItemModel}))
				Expect(virtualizeTableV2OptionsModel.IsIncludedColumns).To(Equal(core.StringPtr("Y, Y, N")))
				Expect(virtualizeTableV2OptionsModel.Replace).To(Equal(core.BoolPtr(false)))
				Expect(virtualizeTableV2OptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
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
			mockDate := CreateMockDate()
			Expect(mockDate).ToNot(BeNil())
		})
		It(`Invoke CreateMockDateTime() successfully`, func() {
			mockDateTime := CreateMockDateTime()
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

func CreateMockDate() *strfmt.Date {
	d := strfmt.Date(time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC))
	return &d
}

func CreateMockDateTime() *strfmt.DateTime {
	d := strfmt.DateTime(time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC))
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
