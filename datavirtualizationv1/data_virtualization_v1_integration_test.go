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
	"github.com/IBM/go-sdk-core/v4/core"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/watson-developer-cloud/go-sdk/datavirtualizationv1"
	"os"
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

			dataVirtualizationService, err = datavirtualizationv1.NewDataVirtualizationV1(dataVirtualizationServiceOptions)

			Expect(err).To(BeNil())
			Expect(dataVirtualizationService).ToNot(BeNil())
			Expect(dataVirtualizationService.Service.Options.URL).To(Equal(serviceURL))
		})
	})

	Describe(`GetDatasourceConnections - Get data source connections`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetDatasourceConnections(getDatasourceConnectionsOptions *GetDatasourceConnectionsOptions)`, func() {

			getDatasourceConnectionsOptions := &datavirtualizationv1.GetDatasourceConnectionsOptions{
			}

			datasourceNodesResponseV2, response, err := dataVirtualizationService.GetDatasourceConnections(getDatasourceConnectionsOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(datasourceNodesResponseV2).ToNot(BeNil())

		})
	})

	Describe(`AddDatasourceConnection - Add data source connection`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`AddDatasourceConnection(addDatasourceConnectionOptions *AddDatasourceConnectionOptions)`, func() {

			postDatasourceConnectionParametersPropertiesModel := &datavirtualizationv1.PostDatasourceConnectionParametersProperties{
				AccessToken: core.StringPtr("testString"),
				AccountName: core.StringPtr("testString"),
				ApiKey: core.StringPtr("testString"),
				AuthType: core.StringPtr("testString"),
				ClientID: core.StringPtr("testString"),
				ClientSecret: core.StringPtr("testString"),
				Collection: core.StringPtr("testString"),
				Credentials: core.StringPtr("testString"),
				Database: core.StringPtr("testString"),
				Host: core.StringPtr("testString"),
				HttpPath: core.StringPtr("testString"),
				JarUris: core.StringPtr("testString"),
				JdbcDriver: core.StringPtr("testString"),
				JdbcURL: core.StringPtr("testString"),
				Password: core.StringPtr("testString"),
				Port: core.StringPtr("testString"),
				ProjectID: core.StringPtr("testString"),
				Properties: core.StringPtr("testString"),
				RefreshToken: core.StringPtr("testString"),
				Role: core.StringPtr("testString"),
				SapGatewayURL: core.StringPtr("testString"),
				Server: core.StringPtr("testString"),
				ServiceName: core.StringPtr("testString"),
				Sid: core.StringPtr("testString"),
				Ssl: core.StringPtr("testString"),
				SslCertificate: core.StringPtr("testString"),
				SslCertificateHost: core.StringPtr("testString"),
				SslCertificateValidation: core.StringPtr("testString"),
				Username: core.StringPtr("testString"),
				Warehouse: core.StringPtr("testString"),
			}

			addDatasourceConnectionOptions := &datavirtualizationv1.AddDatasourceConnectionOptions{
				DatasourceType: core.StringPtr("testString"),
				Name: core.StringPtr("testString"),
				OriginCountry: core.StringPtr("testString"),
				Properties: postDatasourceConnectionParametersPropertiesModel,
				AssetCategory: core.StringPtr("testString"),
			}

			postDatasourceConnectionResponse, response, err := dataVirtualizationService.AddDatasourceConnection(addDatasourceConnectionOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))
			Expect(postDatasourceConnectionResponse).ToNot(BeNil())

		})
	})

	Describe(`GrantUserToVirtualTable - Grant user access`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GrantUserToVirtualTable(grantUserToVirtualTableOptions *GrantUserToVirtualTableOptions)`, func() {

			postUserPrivilegesParametersBodyItemModel := &datavirtualizationv1.PostUserPrivilegesParametersBodyItem{
				TableName: core.StringPtr("EMPLOYEE"),
				TableSchema: core.StringPtr("USER999"),
				Authid: core.StringPtr("PUBLIC"),
			}

			grantUserToVirtualTableOptions := &datavirtualizationv1.GrantUserToVirtualTableOptions{
				Body: []datavirtualizationv1.PostUserPrivilegesParametersBodyItem{*postUserPrivilegesParametersBodyItemModel},
			}

			response, err := dataVirtualizationService.GrantUserToVirtualTable(grantUserToVirtualTableOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))

		})
	})

	Describe(`GrantRolesToVirtualizedTable - Grant user role`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GrantRolesToVirtualizedTable(grantRolesToVirtualizedTableOptions *GrantRolesToVirtualizedTableOptions)`, func() {

			postRolePrivilegesParametersBodyItemModel := &datavirtualizationv1.PostRolePrivilegesParametersBodyItem{
				TableName: core.StringPtr("EMPLOYEE"),
				TableSchema: core.StringPtr("USER999"),
				RoleToGrant: core.StringPtr("PUBLIC"),
			}

			grantRolesToVirtualizedTableOptions := &datavirtualizationv1.GrantRolesToVirtualizedTableOptions{
				Body: []datavirtualizationv1.PostRolePrivilegesParametersBodyItem{*postRolePrivilegesParametersBodyItemModel},
			}

			response, err := dataVirtualizationService.GrantRolesToVirtualizedTable(grantRolesToVirtualizedTableOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))

		})
	})

	Describe(`GetTablesForRole - Get virtualized tables by role`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetTablesForRole(getTablesForRoleOptions *GetTablesForRoleOptions)`, func() {

			getTablesForRoleOptions := &datavirtualizationv1.GetTablesForRoleOptions{
				Rolename: core.StringPtr("ADMIN | STEWARD | ENGINEER | USER"),
			}

			tablesForRoleResponse, response, err := dataVirtualizationService.GetTablesForRole(getTablesForRoleOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(tablesForRoleResponse).ToNot(BeNil())

		})
	})

	Describe(`VirtualizeTableV2 - Virtualize table`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`VirtualizeTableV2(virtualizeTableV2Options *VirtualizeTableV2Options)`, func() {

			virtualizeTableParameterSourceTableDefItemModel := &datavirtualizationv1.VirtualizeTableParameterSourceTableDefItem{
				ColumnName: core.StringPtr("Column1"),
				ColumnType: core.StringPtr("INTEGER"),
			}

			virtualizeTableParameterVirtualTableDefItemModel := &datavirtualizationv1.VirtualizeTableParameterVirtualTableDefItem{
				ColumnName: core.StringPtr("Column_1"),
				ColumnType: core.StringPtr("INTEGER"),
			}

			virtualizeTableV2Options := &datavirtualizationv1.VirtualizeTableV2Options{
				SourceName: core.StringPtr("Tab1"),
				SourceTableDef: []datavirtualizationv1.VirtualizeTableParameterSourceTableDefItem{*virtualizeTableParameterSourceTableDefItemModel},
				Sources: []string{`DB210001:"Hjq1"`},
				VirtualName: core.StringPtr("Tab1"),
				VirtualSchema: core.StringPtr("USER999"),
				VirtualTableDef: []datavirtualizationv1.VirtualizeTableParameterVirtualTableDefItem{*virtualizeTableParameterVirtualTableDefItemModel},
				IsIncludedColumns: core.StringPtr("Y, Y, N"),
				Replace: core.BoolPtr(false),
			}

			virtualizeTableResponse, response, err := dataVirtualizationService.VirtualizeTableV2(virtualizeTableV2Options)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))
			Expect(virtualizeTableResponse).ToNot(BeNil())

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
				TableSchema: core.StringPtr("USER999"),
			}

			response, err := dataVirtualizationService.RevokeUserFromObject(revokeUserFromObjectOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))

		})
	})

	Describe(`RevokeRoleFromTableV2 - Delete role`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`RevokeRoleFromTableV2(revokeRoleFromTableV2Options *RevokeRoleFromTableV2Options)`, func() {

			revokeRoleFromTableV2Options := &datavirtualizationv1.RevokeRoleFromTableV2Options{
				RoleToRevoke: core.StringPtr("DV_ENGINEER"),
				TableName: core.StringPtr("EMPLOYEE"),
				TableSchema: core.StringPtr("USER999"),
			}

			response, err := dataVirtualizationService.RevokeRoleFromTableV2(revokeRoleFromTableV2Options)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))

		})
	})

	Describe(`DeleteTable - Delete virtualized table`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`DeleteTable(deleteTableOptions *DeleteTableOptions)`, func() {

			deleteTableOptions := &datavirtualizationv1.DeleteTableOptions{
				SchemaName: core.StringPtr("testString"),
				TableName: core.StringPtr("testString"),
			}

			response, err := dataVirtualizationService.DeleteTable(deleteTableOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))

		})
	})

	Describe(`DeleteDatasourceConnection - Delete data source connection`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`DeleteDatasourceConnection(deleteDatasourceConnectionOptions *DeleteDatasourceConnectionOptions)`, func() {

			deleteDatasourceConnectionOptions := &datavirtualizationv1.DeleteDatasourceConnectionOptions{
				Cid: core.StringPtr("DB210013"),
				ConnectionID: core.StringPtr("75e4d01b-7417-4abc-b267-8ffb393fb970"),
			}

			response, err := dataVirtualizationService.DeleteDatasourceConnection(deleteDatasourceConnectionOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))

		})
	})
})

//
// Utility functions are declared in the unit test file
//
