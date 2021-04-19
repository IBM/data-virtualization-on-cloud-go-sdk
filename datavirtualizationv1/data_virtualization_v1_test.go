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
	"github.com/IBM/data-virtualization/datavirtualizationv1"
	"github.com/IBM/go-sdk-core/v4/core"
	"github.com/go-openapi/strfmt"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
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

	Describe(`AddDatasourceConnection(addDatasourceConnectionOptions *AddDatasourceConnectionOptions)`, func() {
		addDatasourceConnectionPath := "/v2/datasource_connections"
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
				dataVirtualizationService.EnableRetries(0, 0)

				// Invoke operation with nil options model (negative test)
				response, operationErr := dataVirtualizationService.AddDatasourceConnection(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())

				// Construct an instance of the PostDatasourceConnectionParametersV2Properties model
				postDatasourceConnectionParametersV2PropertiesModel := new(datavirtualizationv1.PostDatasourceConnectionParametersV2Properties)
				postDatasourceConnectionParametersV2PropertiesModel.AccessToken = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.AccountName = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.ApiKey = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.AuthType = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.ClientID = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.ClientSecret = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.Credentials = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.Database = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.Host = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.HttpPath = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.JarUris = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.JdbcDriver = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.JdbcURL = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.Password = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.Port = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.ProjectID = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.Properties = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.RefreshToken = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.SapGatewayURL = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.Server = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.ServiceName = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.Sid = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.Ssl = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.SslCertificate = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.SslCertificateHost = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.SslCertificateValidation = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.Username = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.Warehouse = core.StringPtr("testString")

				// Construct an instance of the AddDatasourceConnectionOptions model
				addDatasourceConnectionOptionsModel := new(datavirtualizationv1.AddDatasourceConnectionOptions)
				addDatasourceConnectionOptionsModel.DatasourceType = core.StringPtr("testString")
				addDatasourceConnectionOptionsModel.Name = core.StringPtr("testString")
				addDatasourceConnectionOptionsModel.OriginCountry = core.StringPtr("testString")
				addDatasourceConnectionOptionsModel.Properties = postDatasourceConnectionParametersV2PropertiesModel
				addDatasourceConnectionOptionsModel.AssetCategory = core.StringPtr("testString")
				addDatasourceConnectionOptionsModel.RemoteNodes = core.StringPtr("testString")
				addDatasourceConnectionOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				response, operationErr = dataVirtualizationService.AddDatasourceConnection(addDatasourceConnectionOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Disable retries and test again
				dataVirtualizationService.DisableRetries()
				response, operationErr = dataVirtualizationService.AddDatasourceConnection(addDatasourceConnectionOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
			})
			It(`Invoke AddDatasourceConnection with error: Operation validation and request error`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())

				// Construct an instance of the PostDatasourceConnectionParametersV2Properties model
				postDatasourceConnectionParametersV2PropertiesModel := new(datavirtualizationv1.PostDatasourceConnectionParametersV2Properties)
				postDatasourceConnectionParametersV2PropertiesModel.AccessToken = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.AccountName = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.ApiKey = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.AuthType = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.ClientID = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.ClientSecret = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.Credentials = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.Database = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.Host = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.HttpPath = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.JarUris = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.JdbcDriver = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.JdbcURL = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.Password = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.Port = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.ProjectID = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.Properties = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.RefreshToken = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.SapGatewayURL = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.Server = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.ServiceName = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.Sid = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.Ssl = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.SslCertificate = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.SslCertificateHost = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.SslCertificateValidation = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.Username = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.Warehouse = core.StringPtr("testString")

				// Construct an instance of the AddDatasourceConnectionOptions model
				addDatasourceConnectionOptionsModel := new(datavirtualizationv1.AddDatasourceConnectionOptions)
				addDatasourceConnectionOptionsModel.DatasourceType = core.StringPtr("testString")
				addDatasourceConnectionOptionsModel.Name = core.StringPtr("testString")
				addDatasourceConnectionOptionsModel.OriginCountry = core.StringPtr("testString")
				addDatasourceConnectionOptionsModel.Properties = postDatasourceConnectionParametersV2PropertiesModel
				addDatasourceConnectionOptionsModel.AssetCategory = core.StringPtr("testString")
				addDatasourceConnectionOptionsModel.RemoteNodes = core.StringPtr("testString")
				addDatasourceConnectionOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := dataVirtualizationService.SetServiceURL("")
				Expect(err).To(BeNil())
				response, operationErr := dataVirtualizationService.AddDatasourceConnection(addDatasourceConnectionOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				// Construct a second instance of the AddDatasourceConnectionOptions model with no property values
				addDatasourceConnectionOptionsModelNew := new(datavirtualizationv1.AddDatasourceConnectionOptions)
				// Invoke operation with invalid model (negative test)
				response, operationErr = dataVirtualizationService.AddDatasourceConnection(addDatasourceConnectionOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
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

					res.WriteHeader(200)
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
	Describe(`GetDatasourceNodes(getDatasourceNodesOptions *GetDatasourceNodesOptions) - Operation response error`, func() {
		getDatasourceNodesPath := "/v2/datasource_nodes"
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getDatasourceNodesPath))
					Expect(req.Method).To(Equal("GET"))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke GetDatasourceNodes with error: Operation response processing error`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())

				// Construct an instance of the GetDatasourceNodesOptions model
				getDatasourceNodesOptionsModel := new(datavirtualizationv1.GetDatasourceNodesOptions)
				getDatasourceNodesOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := dataVirtualizationService.GetDatasourceNodes(getDatasourceNodesOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				dataVirtualizationService.EnableRetries(0, 0)
				result, response, operationErr = dataVirtualizationService.GetDatasourceNodes(getDatasourceNodesOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})

	Describe(`GetDatasourceNodes(getDatasourceNodesOptions *GetDatasourceNodesOptions)`, func() {
		getDatasourceNodesPath := "/v2/datasource_nodes"
		var serverSleepTime time.Duration
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				serverSleepTime = 0
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getDatasourceNodesPath))
					Expect(req.Method).To(Equal("GET"))

					// Sleep a short time to support a timeout test
					time.Sleep(serverSleepTime)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"datasource_nodes_array": [{"node_name": "NodeName", "node_description": "NodeDescription", "agent_class": "AgentClass", "hostname": "Hostname", "port": "Port", "os_user": "OsUser", "is_docker": "IsDocker", "dscount": "Dscount", "data_sources": [{"cid": "Cid", "dbname": "Dbname", "srchostname": "Srchostname", "srcport": "Srcport", "srctype": "Srctype", "usr": "Usr", "uri": "URI", "status": "Status", "connection_name": "ConnectionName"}]}]}`)
				}))
			})
			It(`Invoke GetDatasourceNodes successfully`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())
				dataVirtualizationService.EnableRetries(0, 0)

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := dataVirtualizationService.GetDatasourceNodes(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the GetDatasourceNodesOptions model
				getDatasourceNodesOptionsModel := new(datavirtualizationv1.GetDatasourceNodesOptions)
				getDatasourceNodesOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = dataVirtualizationService.GetDatasourceNodes(getDatasourceNodesOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				serverSleepTime = 100 * time.Millisecond
				_, _, operationErr = dataVirtualizationService.GetDatasourceNodesWithContext(ctx, getDatasourceNodesOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
				serverSleepTime = time.Duration(0)

				// Disable retries and test again
				dataVirtualizationService.DisableRetries()
				result, response, operationErr = dataVirtualizationService.GetDatasourceNodes(getDatasourceNodesOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				serverSleepTime = 100 * time.Millisecond
				_, _, operationErr = dataVirtualizationService.GetDatasourceNodesWithContext(ctx, getDatasourceNodesOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
				serverSleepTime = time.Duration(0)
			})
			It(`Invoke GetDatasourceNodes with error: Operation request error`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())

				// Construct an instance of the GetDatasourceNodesOptions model
				getDatasourceNodesOptionsModel := new(datavirtualizationv1.GetDatasourceNodesOptions)
				getDatasourceNodesOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := dataVirtualizationService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := dataVirtualizationService.GetDatasourceNodes(getDatasourceNodesOptionsModel)
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

	Describe(`GrantUserToObject(grantUserToObjectOptions *GrantUserToObjectOptions)`, func() {
		grantUserToObjectPath := "/v2/privileges/users"
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(grantUserToObjectPath))
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

					res.WriteHeader(200)
				}))
			})
			It(`Invoke GrantUserToObject successfully`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())
				dataVirtualizationService.EnableRetries(0, 0)

				// Invoke operation with nil options model (negative test)
				response, operationErr := dataVirtualizationService.GrantUserToObject(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())

				// Construct an instance of the GrantUserToObjectRequestBodyItem model
				grantUserToObjectRequestBodyItemModel := new(datavirtualizationv1.GrantUserToObjectRequestBodyItem)
				grantUserToObjectRequestBodyItemModel.ObjectName = core.StringPtr("EMPLOYEE")
				grantUserToObjectRequestBodyItemModel.ObjectSchema = core.StringPtr("USER999")
				grantUserToObjectRequestBodyItemModel.Authid = core.StringPtr("PUBLIC")

				// Construct an instance of the GrantUserToObjectOptions model
				grantUserToObjectOptionsModel := new(datavirtualizationv1.GrantUserToObjectOptions)
				grantUserToObjectOptionsModel.Body = []datavirtualizationv1.GrantUserToObjectRequestBodyItem{*grantUserToObjectRequestBodyItemModel}
				grantUserToObjectOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				response, operationErr = dataVirtualizationService.GrantUserToObject(grantUserToObjectOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Disable retries and test again
				dataVirtualizationService.DisableRetries()
				response, operationErr = dataVirtualizationService.GrantUserToObject(grantUserToObjectOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
			})
			It(`Invoke GrantUserToObject with error: Operation validation and request error`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())

				// Construct an instance of the GrantUserToObjectRequestBodyItem model
				grantUserToObjectRequestBodyItemModel := new(datavirtualizationv1.GrantUserToObjectRequestBodyItem)
				grantUserToObjectRequestBodyItemModel.ObjectName = core.StringPtr("EMPLOYEE")
				grantUserToObjectRequestBodyItemModel.ObjectSchema = core.StringPtr("USER999")
				grantUserToObjectRequestBodyItemModel.Authid = core.StringPtr("PUBLIC")

				// Construct an instance of the GrantUserToObjectOptions model
				grantUserToObjectOptionsModel := new(datavirtualizationv1.GrantUserToObjectOptions)
				grantUserToObjectOptionsModel.Body = []datavirtualizationv1.GrantUserToObjectRequestBodyItem{*grantUserToObjectRequestBodyItemModel}
				grantUserToObjectOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := dataVirtualizationService.SetServiceURL("")
				Expect(err).To(BeNil())
				response, operationErr := dataVirtualizationService.GrantUserToObject(grantUserToObjectOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				// Construct a second instance of the GrantUserToObjectOptions model with no property values
				grantUserToObjectOptionsModelNew := new(datavirtualizationv1.GrantUserToObjectOptions)
				// Invoke operation with invalid model (negative test)
				response, operationErr = dataVirtualizationService.GrantUserToObject(grantUserToObjectOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
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

					res.WriteHeader(200)
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

				// Construct an instance of the RevokeUserFromObjectRequestBodyItem model
				revokeUserFromObjectRequestBodyItemModel := new(datavirtualizationv1.RevokeUserFromObjectRequestBodyItem)
				revokeUserFromObjectRequestBodyItemModel.ObjectName = core.StringPtr("EMPLOYEE")
				revokeUserFromObjectRequestBodyItemModel.ObjectSchema = core.StringPtr("USER999")
				revokeUserFromObjectRequestBodyItemModel.Authid = core.StringPtr("PUBLIC")

				// Construct an instance of the RevokeUserFromObjectOptions model
				revokeUserFromObjectOptionsModel := new(datavirtualizationv1.RevokeUserFromObjectOptions)
				revokeUserFromObjectOptionsModel.Body = []datavirtualizationv1.RevokeUserFromObjectRequestBodyItem{*revokeUserFromObjectRequestBodyItemModel}
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

				// Construct an instance of the RevokeUserFromObjectRequestBodyItem model
				revokeUserFromObjectRequestBodyItemModel := new(datavirtualizationv1.RevokeUserFromObjectRequestBodyItem)
				revokeUserFromObjectRequestBodyItemModel.ObjectName = core.StringPtr("EMPLOYEE")
				revokeUserFromObjectRequestBodyItemModel.ObjectSchema = core.StringPtr("USER999")
				revokeUserFromObjectRequestBodyItemModel.Authid = core.StringPtr("PUBLIC")

				// Construct an instance of the RevokeUserFromObjectOptions model
				revokeUserFromObjectOptionsModel := new(datavirtualizationv1.RevokeUserFromObjectOptions)
				revokeUserFromObjectOptionsModel.Body = []datavirtualizationv1.RevokeUserFromObjectRequestBodyItem{*revokeUserFromObjectRequestBodyItemModel}
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

					Expect(req.URL.Query()["authid"]).To(Equal([]string{"PUBLIC"}))

					Expect(req.URL.Query()["object_name"]).To(Equal([]string{"EMPLOYEE"}))

					Expect(req.URL.Query()["object_schema"]).To(Equal([]string{"USER999"}))

					res.WriteHeader(200)
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

				// Construct an instance of the GrantRolesToVirtualizedTableOptions model
				grantRolesToVirtualizedTableOptionsModel := new(datavirtualizationv1.GrantRolesToVirtualizedTableOptions)
				grantRolesToVirtualizedTableOptionsModel.Authid = core.StringPtr("PUBLIC")
				grantRolesToVirtualizedTableOptionsModel.ObjectName = core.StringPtr("EMPLOYEE")
				grantRolesToVirtualizedTableOptionsModel.ObjectSchema = core.StringPtr("USER999")
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
			It(`Invoke GrantRolesToVirtualizedTable with error: Operation validation and request error`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())

				// Construct an instance of the GrantRolesToVirtualizedTableOptions model
				grantRolesToVirtualizedTableOptionsModel := new(datavirtualizationv1.GrantRolesToVirtualizedTableOptions)
				grantRolesToVirtualizedTableOptionsModel.Authid = core.StringPtr("PUBLIC")
				grantRolesToVirtualizedTableOptionsModel.ObjectName = core.StringPtr("EMPLOYEE")
				grantRolesToVirtualizedTableOptionsModel.ObjectSchema = core.StringPtr("USER999")
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

	Describe(`RevokeRoleFromObjectV2(revokeRoleFromObjectV2Options *RevokeRoleFromObjectV2Options)`, func() {
		revokeRoleFromObjectV2Path := "/v2/privileges/roles"
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(revokeRoleFromObjectV2Path))
					Expect(req.Method).To(Equal("DELETE"))

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

					res.WriteHeader(200)
				}))
			})
			It(`Invoke RevokeRoleFromObjectV2 successfully`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())
				dataVirtualizationService.EnableRetries(0, 0)

				// Invoke operation with nil options model (negative test)
				response, operationErr := dataVirtualizationService.RevokeRoleFromObjectV2(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())

				// Construct an instance of the RevokeRoleFromObjectV2RequestBodyItem model
				revokeRoleFromObjectV2RequestBodyItemModel := new(datavirtualizationv1.RevokeRoleFromObjectV2RequestBodyItem)
				revokeRoleFromObjectV2RequestBodyItemModel.ObjectName = core.StringPtr("EMPLOYEE")
				revokeRoleFromObjectV2RequestBodyItemModel.ObjectSchema = core.StringPtr("USER999")
				revokeRoleFromObjectV2RequestBodyItemModel.RoleToRevoke = core.StringPtr("DV_ENGINEER")

				// Construct an instance of the RevokeRoleFromObjectV2Options model
				revokeRoleFromObjectV2OptionsModel := new(datavirtualizationv1.RevokeRoleFromObjectV2Options)
				revokeRoleFromObjectV2OptionsModel.Body = []datavirtualizationv1.RevokeRoleFromObjectV2RequestBodyItem{*revokeRoleFromObjectV2RequestBodyItemModel}
				revokeRoleFromObjectV2OptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				response, operationErr = dataVirtualizationService.RevokeRoleFromObjectV2(revokeRoleFromObjectV2OptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Disable retries and test again
				dataVirtualizationService.DisableRetries()
				response, operationErr = dataVirtualizationService.RevokeRoleFromObjectV2(revokeRoleFromObjectV2OptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
			})
			It(`Invoke RevokeRoleFromObjectV2 with error: Operation request error`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())

				// Construct an instance of the RevokeRoleFromObjectV2RequestBodyItem model
				revokeRoleFromObjectV2RequestBodyItemModel := new(datavirtualizationv1.RevokeRoleFromObjectV2RequestBodyItem)
				revokeRoleFromObjectV2RequestBodyItemModel.ObjectName = core.StringPtr("EMPLOYEE")
				revokeRoleFromObjectV2RequestBodyItemModel.ObjectSchema = core.StringPtr("USER999")
				revokeRoleFromObjectV2RequestBodyItemModel.RoleToRevoke = core.StringPtr("DV_ENGINEER")

				// Construct an instance of the RevokeRoleFromObjectV2Options model
				revokeRoleFromObjectV2OptionsModel := new(datavirtualizationv1.RevokeRoleFromObjectV2Options)
				revokeRoleFromObjectV2OptionsModel.Body = []datavirtualizationv1.RevokeRoleFromObjectV2RequestBodyItem{*revokeRoleFromObjectV2RequestBodyItemModel}
				revokeRoleFromObjectV2OptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := dataVirtualizationService.SetServiceURL("")
				Expect(err).To(BeNil())
				response, operationErr := dataVirtualizationService.RevokeRoleFromObjectV2(revokeRoleFromObjectV2OptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetObjectsForRole(getObjectsForRoleOptions *GetObjectsForRoleOptions) - Operation response error`, func() {
		getObjectsForRolePath := "/v1/privileges/objects/role/User"
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getObjectsForRolePath))
					Expect(req.Method).To(Equal("GET"))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke GetObjectsForRole with error: Operation response processing error`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())

				// Construct an instance of the GetObjectsForRoleOptions model
				getObjectsForRoleOptionsModel := new(datavirtualizationv1.GetObjectsForRoleOptions)
				getObjectsForRoleOptionsModel.Rolename = core.StringPtr("User")
				getObjectsForRoleOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := dataVirtualizationService.GetObjectsForRole(getObjectsForRoleOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				dataVirtualizationService.EnableRetries(0, 0)
				result, response, operationErr = dataVirtualizationService.GetObjectsForRole(getObjectsForRoleOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})

	Describe(`GetObjectsForRole(getObjectsForRoleOptions *GetObjectsForRoleOptions)`, func() {
		getObjectsForRolePath := "/v1/privileges/objects/role/User"
		var serverSleepTime time.Duration
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				serverSleepTime = 0
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getObjectsForRolePath))
					Expect(req.Method).To(Equal("GET"))

					// Sleep a short time to support a timeout test
					time.Sleep(serverSleepTime)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"objects": [{"object_name": "ObjectName", "object_schema": "ObjectSchema", "object_type": "ObjectType"}]}`)
				}))
			})
			It(`Invoke GetObjectsForRole successfully`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())
				dataVirtualizationService.EnableRetries(0, 0)

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := dataVirtualizationService.GetObjectsForRole(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the GetObjectsForRoleOptions model
				getObjectsForRoleOptionsModel := new(datavirtualizationv1.GetObjectsForRoleOptions)
				getObjectsForRoleOptionsModel.Rolename = core.StringPtr("User")
				getObjectsForRoleOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = dataVirtualizationService.GetObjectsForRole(getObjectsForRoleOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				serverSleepTime = 100 * time.Millisecond
				_, _, operationErr = dataVirtualizationService.GetObjectsForRoleWithContext(ctx, getObjectsForRoleOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
				serverSleepTime = time.Duration(0)

				// Disable retries and test again
				dataVirtualizationService.DisableRetries()
				result, response, operationErr = dataVirtualizationService.GetObjectsForRole(getObjectsForRoleOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				serverSleepTime = 100 * time.Millisecond
				_, _, operationErr = dataVirtualizationService.GetObjectsForRoleWithContext(ctx, getObjectsForRoleOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
				serverSleepTime = time.Duration(0)
			})
			It(`Invoke GetObjectsForRole with error: Operation validation and request error`, func() {
				dataVirtualizationService, serviceErr := datavirtualizationv1.NewDataVirtualizationV1(&datavirtualizationv1.DataVirtualizationV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(dataVirtualizationService).ToNot(BeNil())

				// Construct an instance of the GetObjectsForRoleOptions model
				getObjectsForRoleOptionsModel := new(datavirtualizationv1.GetObjectsForRoleOptions)
				getObjectsForRoleOptionsModel.Rolename = core.StringPtr("User")
				getObjectsForRoleOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := dataVirtualizationService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := dataVirtualizationService.GetObjectsForRole(getObjectsForRoleOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the GetObjectsForRoleOptions model with no property values
				getObjectsForRoleOptionsModelNew := new(datavirtualizationv1.GetObjectsForRoleOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = dataVirtualizationService.GetObjectsForRole(getObjectsForRoleOptionsModelNew)
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

				// Construct an instance of the VirtualizeTableV2RequestSourceTableDefItem model
				virtualizeTableV2RequestSourceTableDefItemModel := new(datavirtualizationv1.VirtualizeTableV2RequestSourceTableDefItem)
				virtualizeTableV2RequestSourceTableDefItemModel.ColumnName = core.StringPtr("Column1")
				virtualizeTableV2RequestSourceTableDefItemModel.ColumnType = core.StringPtr("INTEGER")

				// Construct an instance of the VirtualizeTableV2RequestVirtualTableDefItem model
				virtualizeTableV2RequestVirtualTableDefItemModel := new(datavirtualizationv1.VirtualizeTableV2RequestVirtualTableDefItem)
				virtualizeTableV2RequestVirtualTableDefItemModel.ColumnName = core.StringPtr("Column_1")
				virtualizeTableV2RequestVirtualTableDefItemModel.ColumnType = core.StringPtr("INTEGER")

				// Construct an instance of the VirtualizeTableV2Options model
				virtualizeTableV2OptionsModel := new(datavirtualizationv1.VirtualizeTableV2Options)
				virtualizeTableV2OptionsModel.SourceName = core.StringPtr("Tab1")
				virtualizeTableV2OptionsModel.SourceTableDef = []datavirtualizationv1.VirtualizeTableV2RequestSourceTableDefItem{*virtualizeTableV2RequestSourceTableDefItemModel}
				virtualizeTableV2OptionsModel.Sources = []string{`DB210001:"Hjq1"`}
				virtualizeTableV2OptionsModel.VirtualName = core.StringPtr("Tab1")
				virtualizeTableV2OptionsModel.VirtualSchema = core.StringPtr("USER999")
				virtualizeTableV2OptionsModel.VirtualTableDef = []datavirtualizationv1.VirtualizeTableV2RequestVirtualTableDefItem{*virtualizeTableV2RequestVirtualTableDefItemModel}
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
					fmt.Fprintf(res, "%s", `{"message": "Message"}`)
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

				// Construct an instance of the VirtualizeTableV2RequestSourceTableDefItem model
				virtualizeTableV2RequestSourceTableDefItemModel := new(datavirtualizationv1.VirtualizeTableV2RequestSourceTableDefItem)
				virtualizeTableV2RequestSourceTableDefItemModel.ColumnName = core.StringPtr("Column1")
				virtualizeTableV2RequestSourceTableDefItemModel.ColumnType = core.StringPtr("INTEGER")

				// Construct an instance of the VirtualizeTableV2RequestVirtualTableDefItem model
				virtualizeTableV2RequestVirtualTableDefItemModel := new(datavirtualizationv1.VirtualizeTableV2RequestVirtualTableDefItem)
				virtualizeTableV2RequestVirtualTableDefItemModel.ColumnName = core.StringPtr("Column_1")
				virtualizeTableV2RequestVirtualTableDefItemModel.ColumnType = core.StringPtr("INTEGER")

				// Construct an instance of the VirtualizeTableV2Options model
				virtualizeTableV2OptionsModel := new(datavirtualizationv1.VirtualizeTableV2Options)
				virtualizeTableV2OptionsModel.SourceName = core.StringPtr("Tab1")
				virtualizeTableV2OptionsModel.SourceTableDef = []datavirtualizationv1.VirtualizeTableV2RequestSourceTableDefItem{*virtualizeTableV2RequestSourceTableDefItemModel}
				virtualizeTableV2OptionsModel.Sources = []string{`DB210001:"Hjq1"`}
				virtualizeTableV2OptionsModel.VirtualName = core.StringPtr("Tab1")
				virtualizeTableV2OptionsModel.VirtualSchema = core.StringPtr("USER999")
				virtualizeTableV2OptionsModel.VirtualTableDef = []datavirtualizationv1.VirtualizeTableV2RequestVirtualTableDefItem{*virtualizeTableV2RequestVirtualTableDefItemModel}
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

				// Construct an instance of the VirtualizeTableV2RequestSourceTableDefItem model
				virtualizeTableV2RequestSourceTableDefItemModel := new(datavirtualizationv1.VirtualizeTableV2RequestSourceTableDefItem)
				virtualizeTableV2RequestSourceTableDefItemModel.ColumnName = core.StringPtr("Column1")
				virtualizeTableV2RequestSourceTableDefItemModel.ColumnType = core.StringPtr("INTEGER")

				// Construct an instance of the VirtualizeTableV2RequestVirtualTableDefItem model
				virtualizeTableV2RequestVirtualTableDefItemModel := new(datavirtualizationv1.VirtualizeTableV2RequestVirtualTableDefItem)
				virtualizeTableV2RequestVirtualTableDefItemModel.ColumnName = core.StringPtr("Column_1")
				virtualizeTableV2RequestVirtualTableDefItemModel.ColumnType = core.StringPtr("INTEGER")

				// Construct an instance of the VirtualizeTableV2Options model
				virtualizeTableV2OptionsModel := new(datavirtualizationv1.VirtualizeTableV2Options)
				virtualizeTableV2OptionsModel.SourceName = core.StringPtr("Tab1")
				virtualizeTableV2OptionsModel.SourceTableDef = []datavirtualizationv1.VirtualizeTableV2RequestSourceTableDefItem{*virtualizeTableV2RequestSourceTableDefItemModel}
				virtualizeTableV2OptionsModel.Sources = []string{`DB210001:"Hjq1"`}
				virtualizeTableV2OptionsModel.VirtualName = core.StringPtr("Tab1")
				virtualizeTableV2OptionsModel.VirtualSchema = core.StringPtr("USER999")
				virtualizeTableV2OptionsModel.VirtualTableDef = []datavirtualizationv1.VirtualizeTableV2RequestVirtualTableDefItem{*virtualizeTableV2RequestVirtualTableDefItemModel}
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

					res.WriteHeader(200)
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
				deleteTableOptionsModel.ObjectName = core.StringPtr("testString")
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
				deleteTableOptionsModel.ObjectName = core.StringPtr("testString")
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
				// Construct an instance of the PostDatasourceConnectionParametersV2Properties model
				postDatasourceConnectionParametersV2PropertiesModel := new(datavirtualizationv1.PostDatasourceConnectionParametersV2Properties)
				Expect(postDatasourceConnectionParametersV2PropertiesModel).ToNot(BeNil())
				postDatasourceConnectionParametersV2PropertiesModel.AccessToken = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.AccountName = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.ApiKey = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.AuthType = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.ClientID = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.ClientSecret = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.Credentials = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.Database = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.Host = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.HttpPath = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.JarUris = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.JdbcDriver = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.JdbcURL = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.Password = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.Port = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.ProjectID = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.Properties = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.RefreshToken = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.SapGatewayURL = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.Server = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.ServiceName = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.Sid = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.Ssl = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.SslCertificate = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.SslCertificateHost = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.SslCertificateValidation = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.Username = core.StringPtr("testString")
				postDatasourceConnectionParametersV2PropertiesModel.Warehouse = core.StringPtr("testString")
				Expect(postDatasourceConnectionParametersV2PropertiesModel.AccessToken).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersV2PropertiesModel.AccountName).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersV2PropertiesModel.ApiKey).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersV2PropertiesModel.AuthType).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersV2PropertiesModel.ClientID).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersV2PropertiesModel.ClientSecret).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersV2PropertiesModel.Credentials).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersV2PropertiesModel.Database).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersV2PropertiesModel.Host).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersV2PropertiesModel.HttpPath).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersV2PropertiesModel.JarUris).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersV2PropertiesModel.JdbcDriver).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersV2PropertiesModel.JdbcURL).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersV2PropertiesModel.Password).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersV2PropertiesModel.Port).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersV2PropertiesModel.ProjectID).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersV2PropertiesModel.Properties).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersV2PropertiesModel.RefreshToken).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersV2PropertiesModel.SapGatewayURL).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersV2PropertiesModel.Server).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersV2PropertiesModel.ServiceName).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersV2PropertiesModel.Sid).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersV2PropertiesModel.Ssl).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersV2PropertiesModel.SslCertificate).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersV2PropertiesModel.SslCertificateHost).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersV2PropertiesModel.SslCertificateValidation).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersV2PropertiesModel.Username).To(Equal(core.StringPtr("testString")))
				Expect(postDatasourceConnectionParametersV2PropertiesModel.Warehouse).To(Equal(core.StringPtr("testString")))

				// Construct an instance of the AddDatasourceConnectionOptions model
				addDatasourceConnectionOptionsDatasourceType := "testString"
				addDatasourceConnectionOptionsName := "testString"
				addDatasourceConnectionOptionsOriginCountry := "testString"
				var addDatasourceConnectionOptionsProperties *datavirtualizationv1.PostDatasourceConnectionParametersV2Properties = nil
				addDatasourceConnectionOptionsModel := dataVirtualizationService.NewAddDatasourceConnectionOptions(addDatasourceConnectionOptionsDatasourceType, addDatasourceConnectionOptionsName, addDatasourceConnectionOptionsOriginCountry, addDatasourceConnectionOptionsProperties)
				addDatasourceConnectionOptionsModel.SetDatasourceType("testString")
				addDatasourceConnectionOptionsModel.SetName("testString")
				addDatasourceConnectionOptionsModel.SetOriginCountry("testString")
				addDatasourceConnectionOptionsModel.SetProperties(postDatasourceConnectionParametersV2PropertiesModel)
				addDatasourceConnectionOptionsModel.SetAssetCategory("testString")
				addDatasourceConnectionOptionsModel.SetRemoteNodes("testString")
				addDatasourceConnectionOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(addDatasourceConnectionOptionsModel).ToNot(BeNil())
				Expect(addDatasourceConnectionOptionsModel.DatasourceType).To(Equal(core.StringPtr("testString")))
				Expect(addDatasourceConnectionOptionsModel.Name).To(Equal(core.StringPtr("testString")))
				Expect(addDatasourceConnectionOptionsModel.OriginCountry).To(Equal(core.StringPtr("testString")))
				Expect(addDatasourceConnectionOptionsModel.Properties).To(Equal(postDatasourceConnectionParametersV2PropertiesModel))
				Expect(addDatasourceConnectionOptionsModel.AssetCategory).To(Equal(core.StringPtr("testString")))
				Expect(addDatasourceConnectionOptionsModel.RemoteNodes).To(Equal(core.StringPtr("testString")))
				Expect(addDatasourceConnectionOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewDeleteDatasourceConnectionOptions successfully`, func() {
				// Construct an instance of the DeleteDatasourceConnectionOptions model
				deleteDatasourceConnectionOptionsCid := "DB210013"
				deleteDatasourceConnectionOptionsConnectionID := "75e4d01b-7417-4abc-b267-8ffb393fb970"
				deleteDatasourceConnectionOptionsModel := dataVirtualizationService.NewDeleteDatasourceConnectionOptions(deleteDatasourceConnectionOptionsCid, deleteDatasourceConnectionOptionsConnectionID)
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
				objectName := "testString"
				deleteTableOptionsModel := dataVirtualizationService.NewDeleteTableOptions(schemaName, objectName)
				deleteTableOptionsModel.SetSchemaName("testString")
				deleteTableOptionsModel.SetObjectName("testString")
				deleteTableOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(deleteTableOptionsModel).ToNot(BeNil())
				Expect(deleteTableOptionsModel.SchemaName).To(Equal(core.StringPtr("testString")))
				Expect(deleteTableOptionsModel.ObjectName).To(Equal(core.StringPtr("testString")))
				Expect(deleteTableOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewGetDatasourceNodesOptions successfully`, func() {
				// Construct an instance of the GetDatasourceNodesOptions model
				getDatasourceNodesOptionsModel := dataVirtualizationService.NewGetDatasourceNodesOptions()
				getDatasourceNodesOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(getDatasourceNodesOptionsModel).ToNot(BeNil())
				Expect(getDatasourceNodesOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewGetObjectsForRoleOptions successfully`, func() {
				// Construct an instance of the GetObjectsForRoleOptions model
				rolename := "User"
				getObjectsForRoleOptionsModel := dataVirtualizationService.NewGetObjectsForRoleOptions(rolename)
				getObjectsForRoleOptionsModel.SetRolename("User")
				getObjectsForRoleOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(getObjectsForRoleOptionsModel).ToNot(BeNil())
				Expect(getObjectsForRoleOptionsModel.Rolename).To(Equal(core.StringPtr("User")))
				Expect(getObjectsForRoleOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewGrantRolesToVirtualizedTableOptions successfully`, func() {
				// Construct an instance of the GrantRolesToVirtualizedTableOptions model
				authid := "PUBLIC"
				objectName := "EMPLOYEE"
				objectSchema := "USER999"
				grantRolesToVirtualizedTableOptionsModel := dataVirtualizationService.NewGrantRolesToVirtualizedTableOptions(authid, objectName, objectSchema)
				grantRolesToVirtualizedTableOptionsModel.SetAuthid("PUBLIC")
				grantRolesToVirtualizedTableOptionsModel.SetObjectName("EMPLOYEE")
				grantRolesToVirtualizedTableOptionsModel.SetObjectSchema("USER999")
				grantRolesToVirtualizedTableOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(grantRolesToVirtualizedTableOptionsModel).ToNot(BeNil())
				Expect(grantRolesToVirtualizedTableOptionsModel.Authid).To(Equal(core.StringPtr("PUBLIC")))
				Expect(grantRolesToVirtualizedTableOptionsModel.ObjectName).To(Equal(core.StringPtr("EMPLOYEE")))
				Expect(grantRolesToVirtualizedTableOptionsModel.ObjectSchema).To(Equal(core.StringPtr("USER999")))
				Expect(grantRolesToVirtualizedTableOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewGrantUserToObjectOptions successfully`, func() {
				// Construct an instance of the GrantUserToObjectRequestBodyItem model
				grantUserToObjectRequestBodyItemModel := new(datavirtualizationv1.GrantUserToObjectRequestBodyItem)
				Expect(grantUserToObjectRequestBodyItemModel).ToNot(BeNil())
				grantUserToObjectRequestBodyItemModel.ObjectName = core.StringPtr("EMPLOYEE")
				grantUserToObjectRequestBodyItemModel.ObjectSchema = core.StringPtr("USER999")
				grantUserToObjectRequestBodyItemModel.Authid = core.StringPtr("PUBLIC")
				Expect(grantUserToObjectRequestBodyItemModel.ObjectName).To(Equal(core.StringPtr("EMPLOYEE")))
				Expect(grantUserToObjectRequestBodyItemModel.ObjectSchema).To(Equal(core.StringPtr("USER999")))
				Expect(grantUserToObjectRequestBodyItemModel.Authid).To(Equal(core.StringPtr("PUBLIC")))

				// Construct an instance of the GrantUserToObjectOptions model
				grantUserToObjectOptionsBody := []datavirtualizationv1.GrantUserToObjectRequestBodyItem{}
				grantUserToObjectOptionsModel := dataVirtualizationService.NewGrantUserToObjectOptions(grantUserToObjectOptionsBody)
				grantUserToObjectOptionsModel.SetBody([]datavirtualizationv1.GrantUserToObjectRequestBodyItem{*grantUserToObjectRequestBodyItemModel})
				grantUserToObjectOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(grantUserToObjectOptionsModel).ToNot(BeNil())
				Expect(grantUserToObjectOptionsModel.Body).To(Equal([]datavirtualizationv1.GrantUserToObjectRequestBodyItem{*grantUserToObjectRequestBodyItemModel}))
				Expect(grantUserToObjectOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewRevokeRoleFromObjectV2Options successfully`, func() {
				// Construct an instance of the RevokeRoleFromObjectV2RequestBodyItem model
				revokeRoleFromObjectV2RequestBodyItemModel := new(datavirtualizationv1.RevokeRoleFromObjectV2RequestBodyItem)
				Expect(revokeRoleFromObjectV2RequestBodyItemModel).ToNot(BeNil())
				revokeRoleFromObjectV2RequestBodyItemModel.ObjectName = core.StringPtr("EMPLOYEE")
				revokeRoleFromObjectV2RequestBodyItemModel.ObjectSchema = core.StringPtr("USER999")
				revokeRoleFromObjectV2RequestBodyItemModel.RoleToRevoke = core.StringPtr("DV_ENGINEER")
				Expect(revokeRoleFromObjectV2RequestBodyItemModel.ObjectName).To(Equal(core.StringPtr("EMPLOYEE")))
				Expect(revokeRoleFromObjectV2RequestBodyItemModel.ObjectSchema).To(Equal(core.StringPtr("USER999")))
				Expect(revokeRoleFromObjectV2RequestBodyItemModel.RoleToRevoke).To(Equal(core.StringPtr("DV_ENGINEER")))

				// Construct an instance of the RevokeRoleFromObjectV2Options model
				revokeRoleFromObjectV2OptionsModel := dataVirtualizationService.NewRevokeRoleFromObjectV2Options()
				revokeRoleFromObjectV2OptionsModel.SetBody([]datavirtualizationv1.RevokeRoleFromObjectV2RequestBodyItem{*revokeRoleFromObjectV2RequestBodyItemModel})
				revokeRoleFromObjectV2OptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(revokeRoleFromObjectV2OptionsModel).ToNot(BeNil())
				Expect(revokeRoleFromObjectV2OptionsModel.Body).To(Equal([]datavirtualizationv1.RevokeRoleFromObjectV2RequestBodyItem{*revokeRoleFromObjectV2RequestBodyItemModel}))
				Expect(revokeRoleFromObjectV2OptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewRevokeUserFromObjectOptions successfully`, func() {
				// Construct an instance of the RevokeUserFromObjectRequestBodyItem model
				revokeUserFromObjectRequestBodyItemModel := new(datavirtualizationv1.RevokeUserFromObjectRequestBodyItem)
				Expect(revokeUserFromObjectRequestBodyItemModel).ToNot(BeNil())
				revokeUserFromObjectRequestBodyItemModel.ObjectName = core.StringPtr("EMPLOYEE")
				revokeUserFromObjectRequestBodyItemModel.ObjectSchema = core.StringPtr("USER999")
				revokeUserFromObjectRequestBodyItemModel.Authid = core.StringPtr("PUBLIC")
				Expect(revokeUserFromObjectRequestBodyItemModel.ObjectName).To(Equal(core.StringPtr("EMPLOYEE")))
				Expect(revokeUserFromObjectRequestBodyItemModel.ObjectSchema).To(Equal(core.StringPtr("USER999")))
				Expect(revokeUserFromObjectRequestBodyItemModel.Authid).To(Equal(core.StringPtr("PUBLIC")))

				// Construct an instance of the RevokeUserFromObjectOptions model
				revokeUserFromObjectOptionsBody := []datavirtualizationv1.RevokeUserFromObjectRequestBodyItem{}
				revokeUserFromObjectOptionsModel := dataVirtualizationService.NewRevokeUserFromObjectOptions(revokeUserFromObjectOptionsBody)
				revokeUserFromObjectOptionsModel.SetBody([]datavirtualizationv1.RevokeUserFromObjectRequestBodyItem{*revokeUserFromObjectRequestBodyItemModel})
				revokeUserFromObjectOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(revokeUserFromObjectOptionsModel).ToNot(BeNil())
				Expect(revokeUserFromObjectOptionsModel.Body).To(Equal([]datavirtualizationv1.RevokeUserFromObjectRequestBodyItem{*revokeUserFromObjectRequestBodyItemModel}))
				Expect(revokeUserFromObjectOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewVirtualizeTableV2Options successfully`, func() {
				// Construct an instance of the VirtualizeTableV2RequestSourceTableDefItem model
				virtualizeTableV2RequestSourceTableDefItemModel := new(datavirtualizationv1.VirtualizeTableV2RequestSourceTableDefItem)
				Expect(virtualizeTableV2RequestSourceTableDefItemModel).ToNot(BeNil())
				virtualizeTableV2RequestSourceTableDefItemModel.ColumnName = core.StringPtr("Column1")
				virtualizeTableV2RequestSourceTableDefItemModel.ColumnType = core.StringPtr("INTEGER")
				Expect(virtualizeTableV2RequestSourceTableDefItemModel.ColumnName).To(Equal(core.StringPtr("Column1")))
				Expect(virtualizeTableV2RequestSourceTableDefItemModel.ColumnType).To(Equal(core.StringPtr("INTEGER")))

				// Construct an instance of the VirtualizeTableV2RequestVirtualTableDefItem model
				virtualizeTableV2RequestVirtualTableDefItemModel := new(datavirtualizationv1.VirtualizeTableV2RequestVirtualTableDefItem)
				Expect(virtualizeTableV2RequestVirtualTableDefItemModel).ToNot(BeNil())
				virtualizeTableV2RequestVirtualTableDefItemModel.ColumnName = core.StringPtr("Column_1")
				virtualizeTableV2RequestVirtualTableDefItemModel.ColumnType = core.StringPtr("INTEGER")
				Expect(virtualizeTableV2RequestVirtualTableDefItemModel.ColumnName).To(Equal(core.StringPtr("Column_1")))
				Expect(virtualizeTableV2RequestVirtualTableDefItemModel.ColumnType).To(Equal(core.StringPtr("INTEGER")))

				// Construct an instance of the VirtualizeTableV2Options model
				virtualizeTableV2OptionsSourceName := "Tab1"
				virtualizeTableV2OptionsSourceTableDef := []datavirtualizationv1.VirtualizeTableV2RequestSourceTableDefItem{}
				virtualizeTableV2OptionsSources := []string{`DB210001:"Hjq1"`}
				virtualizeTableV2OptionsVirtualName := "Tab1"
				virtualizeTableV2OptionsVirtualSchema := "USER999"
				virtualizeTableV2OptionsVirtualTableDef := []datavirtualizationv1.VirtualizeTableV2RequestVirtualTableDefItem{}
				virtualizeTableV2OptionsModel := dataVirtualizationService.NewVirtualizeTableV2Options(virtualizeTableV2OptionsSourceName, virtualizeTableV2OptionsSourceTableDef, virtualizeTableV2OptionsSources, virtualizeTableV2OptionsVirtualName, virtualizeTableV2OptionsVirtualSchema, virtualizeTableV2OptionsVirtualTableDef)
				virtualizeTableV2OptionsModel.SetSourceName("Tab1")
				virtualizeTableV2OptionsModel.SetSourceTableDef([]datavirtualizationv1.VirtualizeTableV2RequestSourceTableDefItem{*virtualizeTableV2RequestSourceTableDefItemModel})
				virtualizeTableV2OptionsModel.SetSources([]string{`DB210001:"Hjq1"`})
				virtualizeTableV2OptionsModel.SetVirtualName("Tab1")
				virtualizeTableV2OptionsModel.SetVirtualSchema("USER999")
				virtualizeTableV2OptionsModel.SetVirtualTableDef([]datavirtualizationv1.VirtualizeTableV2RequestVirtualTableDefItem{*virtualizeTableV2RequestVirtualTableDefItemModel})
				virtualizeTableV2OptionsModel.SetIsIncludedColumns("Y, Y, N")
				virtualizeTableV2OptionsModel.SetReplace(false)
				virtualizeTableV2OptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(virtualizeTableV2OptionsModel).ToNot(BeNil())
				Expect(virtualizeTableV2OptionsModel.SourceName).To(Equal(core.StringPtr("Tab1")))
				Expect(virtualizeTableV2OptionsModel.SourceTableDef).To(Equal([]datavirtualizationv1.VirtualizeTableV2RequestSourceTableDefItem{*virtualizeTableV2RequestSourceTableDefItemModel}))
				Expect(virtualizeTableV2OptionsModel.Sources).To(Equal([]string{`DB210001:"Hjq1"`}))
				Expect(virtualizeTableV2OptionsModel.VirtualName).To(Equal(core.StringPtr("Tab1")))
				Expect(virtualizeTableV2OptionsModel.VirtualSchema).To(Equal(core.StringPtr("USER999")))
				Expect(virtualizeTableV2OptionsModel.VirtualTableDef).To(Equal([]datavirtualizationv1.VirtualizeTableV2RequestVirtualTableDefItem{*virtualizeTableV2RequestVirtualTableDefItemModel}))
				Expect(virtualizeTableV2OptionsModel.IsIncludedColumns).To(Equal(core.StringPtr("Y, Y, N")))
				Expect(virtualizeTableV2OptionsModel.Replace).To(Equal(core.BoolPtr(false)))
				Expect(virtualizeTableV2OptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewVirtualizeTableV2RequestSourceTableDefItem successfully`, func() {
				columnName := "Column1"
				columnType := "INTEGER"
				model, err := dataVirtualizationService.NewVirtualizeTableV2RequestSourceTableDefItem(columnName, columnType)
				Expect(model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewVirtualizeTableV2RequestVirtualTableDefItem successfully`, func() {
				columnName := "Column_1"
				columnType := "INTEGER"
				model, err := dataVirtualizationService.NewVirtualizeTableV2RequestVirtualTableDefItem(columnName, columnType)
				Expect(model).ToNot(BeNil())
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
