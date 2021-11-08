// +build integration

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
	"fmt"
	"log"
	"os"
	"time"

	"github.com/IBM/data-virtualization-on-cloud-go-sdk/datavirtualizationv1"
	"github.com/IBM/go-sdk-core/v5/core"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

/**
 * This file contains an integration test for the datavirtualizationv1 package.
 *
 * Notes:
 *
 * The integration test will automatically skip tests if the required config file is not available.
 */

var _ = Describe(`DataVirtualizationV1 Integration Tests`, func() {

	const externalConfigFile = "../data_virtualization_v1.env"

	var (
		err          error
		dataVirtualizationService *datavirtualizationv1.DataVirtualizationV1
		serviceURL   string
		config       map[string]string
	)

	var shouldSkipTest = func() {
		Skip("External configuration is not available, skipping tests...")
	}

	Describe(`External configuration`, func() {
		It("Successfully load the configuration", func() {
			_, err = os.Stat(externalConfigFile)
			if err != nil {
				Skip("External configuration file not found, skipping tests: " + err.Error())
			}

			os.Setenv("IBM_CREDENTIALS_FILE", externalConfigFile)
			config, err = core.GetServiceProperties(datavirtualizationv1.DefaultServiceName)
			if err != nil {
				Skip("Error loading service properties, skipping tests: " + err.Error())
			}
			serviceURL = config["URL"]
			if serviceURL == "" {
				Skip("Unable to load service URL configuration property, skipping tests")
			}

			fmt.Printf("Service URL: %s\n", serviceURL)
			shouldSkipTest = func() {}
		})
	})

	Describe(`Client initialization`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It("Successfully construct the service client instance", func() {

			dataVirtualizationServiceOptions := &datavirtualizationv1.DataVirtualizationV1Options{}

			dataVirtualizationService, err = datavirtualizationv1.NewDataVirtualizationV1UsingExternalConfig(dataVirtualizationServiceOptions)

			Expect(err).To(BeNil())
			Expect(dataVirtualizationService).ToNot(BeNil())
			Expect(dataVirtualizationService.Service.Options.URL).To(Equal(serviceURL))

			core.SetLogger(core.NewLogger(core.LevelDebug, log.New(GinkgoWriter, "", log.LstdFlags), log.New(GinkgoWriter, "", log.LstdFlags)))
			dataVirtualizationService.EnableRetries(4, 30*time.Second)
		})
	})

	Describe(`ListDatasourceConnections - Get data source connections`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`ListDatasourceConnections(listDatasourceConnectionsOptions *ListDatasourceConnectionsOptions)`, func() {

			listDatasourceConnectionsOptions := &datavirtualizationv1.ListDatasourceConnectionsOptions{
			}

			datasourceConnectionsList, response, err := dataVirtualizationService.ListDatasourceConnections(listDatasourceConnectionsOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(datasourceConnectionsList).ToNot(BeNil())

			//
			// The following status codes aren't covered by tests.
			// Please provide integration tests for these too.
			//
			// 400
			// 401
			// 500
			//
		})
	})

	Describe(`AddDatasourceConnection - Add data source connection`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`AddDatasourceConnection(addDatasourceConnectionOptions *AddDatasourceConnectionOptions)`, func() {

			postDatasourceConnectionParametersPropertiesModel := &datavirtualizationv1.PostDatasourceConnectionParametersProperties{
				AccessToken: core.StringPtr("ya29.Il-_"),
				AccountName: core.StringPtr("ibmdatastage.us-east-1"),
				APIKey: core.StringPtr("ApiKey-a31d60c5-0f7b-4995-a4ae-69bf09d3de50"),
				AuthType: core.StringPtr("Bearer Token"),
				ClientID: core.StringPtr("81571342315"),
				ClientSecret: core.StringPtr("uIn8rVyIRsd"),
				Collection: core.StringPtr("test_collection"),
				Credentials: core.StringPtr("-----BEGIN PRIVATE KEY-----"),
				Database: core.StringPtr("TPCDS"),
				Host: core.StringPtr("192.168.0.1"),
				HTTPPath: core.StringPtr("cliservice"),
				JarUris: core.StringPtr("/v2/asset_files/dbdrivers/ngdbc.jar"),
				JdbcDriver: core.StringPtr("Snowflake"),
				JdbcURL: core.StringPtr("/v2/asset_files/dbdrivers/ngdbc.jar"),
				Password: core.StringPtr("password"),
				Port: core.StringPtr("50000"),
				ProjectID: core.StringPtr("housecanary-com"),
				Properties: core.StringPtr("key=value"),
				RefreshToken: core.StringPtr("1//06uwhP7_312g"),
				Role: core.StringPtr("SYSADMIN"),
				SapGatewayURL: core.StringPtr("https://sapes5.sapdevcenter.com"),
				Server: core.StringPtr("ol_informix1410"),
				ServiceName: core.StringPtr("pdborcl.fyre.ibm.com"),
				Sid: core.StringPtr("orcl"),
				Ssl: core.StringPtr("false"),
				SslCertificate: core.StringPtr("-----BEGIN CERTIFICATE-----"),
				SslCertificateHost: core.StringPtr("test.com"),
				SslCertificateValidation: core.StringPtr("false"),
				Username: core.StringPtr("db2inst1"),
				Warehouse: core.StringPtr("wdpcondev"),
			}

			addDatasourceConnectionOptions := &datavirtualizationv1.AddDatasourceConnectionOptions{
				DatasourceType: core.StringPtr("DB2"),
				Name: core.StringPtr("DB2"),
				OriginCountry: core.StringPtr("us"),
				Properties: postDatasourceConnectionParametersPropertiesModel,
				AssetCategory: core.StringPtr("USER"),
			}

			postDatasourceConnection, response, err := dataVirtualizationService.AddDatasourceConnection(addDatasourceConnectionOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))
			Expect(postDatasourceConnection).ToNot(BeNil())

			//
			// The following status codes aren't covered by tests.
			// Please provide integration tests for these too.
			//
			// 400
			// 401
			// 409
			// 500
			//
		})
	})

	Describe(`GetObjectStoreConnectionsV2 - Gets object store connection details`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetObjectStoreConnectionsV2(getObjectStoreConnectionsV2Options *GetObjectStoreConnectionsV2Options)`, func() {

			getObjectStoreConnectionsV2Options := &datavirtualizationv1.GetObjectStoreConnectionsV2Options{
				JwtAuthUserPayload: core.StringPtr("testString"),
			}

			objStoreConnectionResponseV2, response, err := dataVirtualizationService.GetObjectStoreConnectionsV2(getObjectStoreConnectionsV2Options)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(objStoreConnectionResponseV2).ToNot(BeNil())

			//
			// The following status codes aren't covered by tests.
			// Please provide integration tests for these too.
			//
			// 400
			// 401
			// 500
			//
		})
	})

	Describe(`GrantUserToVirtualTable - Grant user access`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GrantUserToVirtualTable(grantUserToVirtualTableOptions *GrantUserToVirtualTableOptions)`, func() {

			grantUserToVirtualTableOptions := &datavirtualizationv1.GrantUserToVirtualTableOptions{
				TableName: core.StringPtr("EMPLOYEE"),
				TableSchema: core.StringPtr("dv_ibmid_060000s4y5"),
				Authid: core.StringPtr("PUBLIC"),
			}

			response, err := dataVirtualizationService.GrantUserToVirtualTable(grantUserToVirtualTableOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))

			//
			// The following status codes aren't covered by tests.
			// Please provide integration tests for these too.
			//
			// 400
			// 401
			// 500
			//
		})
	})

	Describe(`GrantRolesToVirtualizedTable - Grant user role`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GrantRolesToVirtualizedTable(grantRolesToVirtualizedTableOptions *GrantRolesToVirtualizedTableOptions)`, func() {

			grantRolesToVirtualizedTableOptions := &datavirtualizationv1.GrantRolesToVirtualizedTableOptions{
				TableName: core.StringPtr("EMPLOYEE"),
				TableSchema: core.StringPtr("dv_ibmid_060000s4y5"),
				RoleName: core.StringPtr("PUBLIC"),
			}

			response, err := dataVirtualizationService.GrantRolesToVirtualizedTable(grantRolesToVirtualizedTableOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))

			//
			// The following status codes aren't covered by tests.
			// Please provide integration tests for these too.
			//
			// 400
			// 401
			// 500
			//
		})
	})

	Describe(`ListTablesForRole - Get virtualized tables by role`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`ListTablesForRole(listTablesForRoleOptions *ListTablesForRoleOptions)`, func() {

			listTablesForRoleOptions := &datavirtualizationv1.ListTablesForRoleOptions{
				Rolename: core.StringPtr("MANAGER | STEWARD | ENGINEER | USER"),
			}

			tablesForRoleResponse, response, err := dataVirtualizationService.ListTablesForRole(listTablesForRoleOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(tablesForRoleResponse).ToNot(BeNil())

			//
			// The following status codes aren't covered by tests.
			// Please provide integration tests for these too.
			//
			// 400
			// 401
			// 500
			//
		})
	})

	Describe(`TurnOnPolicyV2 - Turn policy enforcement status on or off`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`TurnOnPolicyV2(turnOnPolicyV2Options *TurnOnPolicyV2Options)`, func() {

			turnOnPolicyV2Options := &datavirtualizationv1.TurnOnPolicyV2Options{
				Status: core.StringPtr("enabled"),
			}

			turnOnPolicyV2Response, response, err := dataVirtualizationService.TurnOnPolicyV2(turnOnPolicyV2Options)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(turnOnPolicyV2Response).ToNot(BeNil())

			//
			// The following status codes aren't covered by tests.
			// Please provide integration tests for these too.
			//
			// 401
			// 500
			//
		})
	})

	Describe(`CheckPolicyStatusV2 - Get policy enforcement status`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`CheckPolicyStatusV2(checkPolicyStatusV2Options *CheckPolicyStatusV2Options)`, func() {

			checkPolicyStatusV2Options := &datavirtualizationv1.CheckPolicyStatusV2Options{
			}

			checkPolicyStatusV2Response, response, err := dataVirtualizationService.CheckPolicyStatusV2(checkPolicyStatusV2Options)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(checkPolicyStatusV2Response).ToNot(BeNil())

			//
			// The following status codes aren't covered by tests.
			// Please provide integration tests for these too.
			//
			// 401
			// 500
			//
		})
	})

	Describe(`DvaasVirtualizeTable - Virtualize table`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`DvaasVirtualizeTable(dvaasVirtualizeTableOptions *DvaasVirtualizeTableOptions)`, func() {

			virtualizeTableParameterSourceTableDefItemModel := &datavirtualizationv1.VirtualizeTableParameterSourceTableDefItem{
				ColumnName: core.StringPtr("Column1"),
				ColumnType: core.StringPtr("INTEGER"),
			}

			virtualizeTableParameterVirtualTableDefItemModel := &datavirtualizationv1.VirtualizeTableParameterVirtualTableDefItem{
				ColumnName: core.StringPtr("Column_1"),
				ColumnType: core.StringPtr("INTEGER"),
			}

			dvaasVirtualizeTableOptions := &datavirtualizationv1.DvaasVirtualizeTableOptions{
				SourceName: core.StringPtr("Tab1"),
				SourceTableDef: []datavirtualizationv1.VirtualizeTableParameterSourceTableDefItem{*virtualizeTableParameterSourceTableDefItemModel},
				Sources: []string{`DB210001:"Hjq1"`},
				VirtualName: core.StringPtr("Tab1"),
				VirtualSchema: core.StringPtr("dv_ibmid_060000s4y5"),
				VirtualTableDef: []datavirtualizationv1.VirtualizeTableParameterVirtualTableDefItem{*virtualizeTableParameterVirtualTableDefItemModel},
				IsIncludedColumns: core.StringPtr("Y, Y, N"),
				Replace: core.BoolPtr(false),
			}

			virtualizeTableResponse, response, err := dataVirtualizationService.DvaasVirtualizeTable(dvaasVirtualizeTableOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))
			Expect(virtualizeTableResponse).ToNot(BeNil())

			//
			// The following status codes aren't covered by tests.
			// Please provide integration tests for these too.
			//
			// 400
			// 401
			// 500
			//
		})
	})

	Describe(`VirtualizeCosV2 - Create a remote table for the ORC or Parquet file on a cloud object store (COS)`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`VirtualizeCosV2(virtualizeCosV2Options *VirtualizeCosV2Options)`, func() {

			virtualizeCosV2RequestVirtualTableDefItemModel := &datavirtualizationv1.VirtualizeCosV2RequestVirtualTableDefItem{
				ColumnName: core.StringPtr("Column_1"),
				ColumnType: core.StringPtr("INTEGER"),
			}

			virtualizeCosV2Options := &datavirtualizationv1.VirtualizeCosV2Options{
				URL: core.StringPtr("s3a://testBucket/home/data.csv"),
				VirtualName: core.StringPtr("testString"),
				VirtualSchema: core.StringPtr("testString"),
				VirtualTableDef: []datavirtualizationv1.VirtualizeCosV2RequestVirtualTableDefItem{*virtualizeCosV2RequestVirtualTableDefItemModel},
				IsReplace: core.BoolPtr(false),
				Options: core.StringPtr("INCPARTS=true"),
				JwtAuthUserPayload: core.StringPtr("testString"),
			}

			successResponse, response, err := dataVirtualizationService.VirtualizeCosV2(virtualizeCosV2Options)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(successResponse).ToNot(BeNil())

			//
			// The following status codes aren't covered by tests.
			// Please provide integration tests for these too.
			//
			// 400
			// 401
			// 500
			//
		})
	})

	Describe(`GetPrimaryCatalog - Get primary catalog ID`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetPrimaryCatalog(getPrimaryCatalogOptions *GetPrimaryCatalogOptions)`, func() {

			getPrimaryCatalogOptions := &datavirtualizationv1.GetPrimaryCatalogOptions{
			}

			primaryCatalogInfo, response, err := dataVirtualizationService.GetPrimaryCatalog(getPrimaryCatalogOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(primaryCatalogInfo).ToNot(BeNil())

			//
			// The following status codes aren't covered by tests.
			// Please provide integration tests for these too.
			//
			// 400
			// 401
			// 500
			//
		})
	})

	Describe(`PostPrimaryCatalog - Add primary catalog`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`PostPrimaryCatalog(postPrimaryCatalogOptions *PostPrimaryCatalogOptions)`, func() {

			postPrimaryCatalogOptions := &datavirtualizationv1.PostPrimaryCatalogOptions{
				GUID: core.StringPtr("d77fc432-9b1a-4938-a2a5-9f37e08041f6"),
			}

			postPrimaryCatalog, response, err := dataVirtualizationService.PostPrimaryCatalog(postPrimaryCatalogOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))
			Expect(postPrimaryCatalog).ToNot(BeNil())

			//
			// The following status codes aren't covered by tests.
			// Please provide integration tests for these too.
			//
			// 400
			// 401
			// 500
			//
		})
	})

	Describe(`PublishAssets - Publish virtual tables to a catalog`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`PublishAssets(publishAssetsOptions *PublishAssetsOptions)`, func() {

			postPrimaryCatalogParametersAssetsItemModel := &datavirtualizationv1.PostPrimaryCatalogParametersAssetsItem{
				Schema: core.StringPtr("db2inst1"),
				Table: core.StringPtr("EMPLOYEE"),
			}

			publishAssetsOptions := &datavirtualizationv1.PublishAssetsOptions{
				CatalogID: core.StringPtr("2b6b9fc5-626c-47a9-a836-56b76c0bc826"),
				AllowDuplicates: core.BoolPtr(false),
				Assets: []datavirtualizationv1.PostPrimaryCatalogParametersAssetsItem{*postPrimaryCatalogParametersAssetsItemModel},
			}

			catalogPublishResponse, response, err := dataVirtualizationService.PublishAssets(publishAssetsOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(catalogPublishResponse).ToNot(BeNil())

			//
			// The following status codes aren't covered by tests.
			// Please provide integration tests for these too.
			//
			// 400
			// 401
			// 500
			//
		})
	})

	Describe(`GetCachesList - List caches`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetCachesList(getCachesListOptions *GetCachesListOptions)`, func() {

			getCachesListOptions := &datavirtualizationv1.GetCachesListOptions{
			}

			cacheListResponse, response, err := dataVirtualizationService.GetCachesList(getCachesListOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(cacheListResponse).ToNot(BeNil())

			//
			// The following status codes aren't covered by tests.
			// Please provide integration tests for these too.
			//
			// 400
			// 401
			// 500
			//
		})
	})

	Describe(`GetCache - List a cache`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetCache(getCacheOptions *GetCacheOptions)`, func() {

			getCacheOptions := &datavirtualizationv1.GetCacheOptions{
				ID: core.StringPtr("DV20210810191252390327"),
			}

			cacheResponse, response, err := dataVirtualizationService.GetCache(getCacheOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(cacheResponse).ToNot(BeNil())

			//
			// The following status codes aren't covered by tests.
			// Please provide integration tests for these too.
			//
			// 400
			// 401
			// 500
			//
		})
	})

	Describe(`GetCacheStorageDetail - Fetch the cache storage`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetCacheStorageDetail(getCacheStorageDetailOptions *GetCacheStorageDetailOptions)`, func() {

			getCacheStorageDetailOptions := &datavirtualizationv1.GetCacheStorageDetailOptions{
			}

			storageDetails, response, err := dataVirtualizationService.GetCacheStorageDetail(getCacheStorageDetailOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(storageDetails).ToNot(BeNil())

			//
			// The following status codes aren't covered by tests.
			// Please provide integration tests for these too.
			//
			// 400
			// 401
			// 500
			//
		})
	})

	Describe(`RevokeUserFromObject - Revoke user acccess`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`RevokeUserFromObject(revokeUserFromObjectOptions *RevokeUserFromObjectOptions)`, func() {

			revokeUserFromObjectOptions := &datavirtualizationv1.RevokeUserFromObjectOptions{
				Authid: core.StringPtr("PUBLIC"),
				TableName: core.StringPtr("EMPLOYEE"),
				TableSchema: core.StringPtr("dv_ibmid_060000s4y5"),
			}

			response, err := dataVirtualizationService.RevokeUserFromObject(revokeUserFromObjectOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))

			//
			// The following status codes aren't covered by tests.
			// Please provide integration tests for these too.
			//
			// 400
			// 401
			// 500
			//
		})
	})

	Describe(`DvaasRevokeRoleFromTable - Delete role`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`DvaasRevokeRoleFromTable(dvaasRevokeRoleFromTableOptions *DvaasRevokeRoleFromTableOptions)`, func() {

			dvaasRevokeRoleFromTableOptions := &datavirtualizationv1.DvaasRevokeRoleFromTableOptions{
				RoleName: core.StringPtr("DV_ENGINEER"),
				TableName: core.StringPtr("EMPLOYEE"),
				TableSchema: core.StringPtr("dv_ibmid_060000s4y5"),
			}

			response, err := dataVirtualizationService.DvaasRevokeRoleFromTable(dvaasRevokeRoleFromTableOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))

			//
			// The following status codes aren't covered by tests.
			// Please provide integration tests for these too.
			//
			// 400
			// 401
			// 500
			//
		})
	})

	Describe(`DeleteTable - Delete virtualized table`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`DeleteTable(deleteTableOptions *DeleteTableOptions)`, func() {

			deleteTableOptions := &datavirtualizationv1.DeleteTableOptions{
				VirtualSchema: core.StringPtr("testString"),
				VirtualName: core.StringPtr("testString"),
			}

			response, err := dataVirtualizationService.DeleteTable(deleteTableOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))

			//
			// The following status codes aren't covered by tests.
			// Please provide integration tests for these too.
			//
			// 400
			// 500
			//
		})
	})

	Describe(`DeletePrimaryCatalog - Delete primary catalog`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`DeletePrimaryCatalog(deletePrimaryCatalogOptions *DeletePrimaryCatalogOptions)`, func() {

			deletePrimaryCatalogOptions := &datavirtualizationv1.DeletePrimaryCatalogOptions{
				GUID: core.StringPtr("d77fc432-9b1a-4938-a2a5-9f37e08041f6"),
			}

			response, err := dataVirtualizationService.DeletePrimaryCatalog(deletePrimaryCatalogOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))

			//
			// The following status codes aren't covered by tests.
			// Please provide integration tests for these too.
			//
			// 400
			// 401
			// 500
			//
		})
	})

	Describe(`DeleteDatasourceConnection - Delete data source connection`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`DeleteDatasourceConnection(deleteDatasourceConnectionOptions *DeleteDatasourceConnectionOptions)`, func() {

			deleteDatasourceConnectionOptions := &datavirtualizationv1.DeleteDatasourceConnectionOptions{
				ConnectionID: core.StringPtr("75e4d01b-7417-4abc-b267-8ffb393fb970"),
				Cid: core.StringPtr("DB210013"),
			}

			response, err := dataVirtualizationService.DeleteDatasourceConnection(deleteDatasourceConnectionOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))

			//
			// The following status codes aren't covered by tests.
			// Please provide integration tests for these too.
			//
			// 400
			// 401
			// 500
			//
		})
	})
})

//
// Utility functions are declared in the unit test file
//
