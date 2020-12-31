// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

// ***************************************************************
// - [#] indicates a test step (e.g. # Go to a page)
// - [*] indicates an assertion (e.g. * Check the title)
// - Use element ID when selecting an element. Create one if none.
// ***************************************************************

// Group: @enterprise @saml

import * as TIMEOUTS from '../../../fixtures/timeouts';
import {getRandomId} from '../../../utils';

// assumes that E20 license is uploaded
// assumes openldap docker available on config default http://localhost:389
// assumes keycloak docker available on default, "http://localhost:8484", realm "mattermost"
// overridable via CYPRESS variables (CYPRESS_keycloakBaseUrl / CYPRESS_keycloakAppName)
// requires {"chromeWebSecurity": false}
describe('guest-accounts -> SAML Guest', () => {
    const loginButtonText = 'SAML';

    const user1 = {
        username: 'guest.test',
        password: 'Password1',
        email: 'guest.test@mmtest.com',
        firstname: 'Guest',
        lastname: 'OneSaml',
        keycloakId: '',
    };
    const userFilter = `username=${user1.username}`;
    const keycloakBaseUrl = Cypress.env('keycloakBaseUrl') || 'http://localhost:8484';
    const keycloakAppName = Cypress.env('keycloakAppName') || 'mattermost';
    const idpUrl = `${keycloakBaseUrl}/auth/realms/${keycloakAppName}/protocol/saml`;
    const idpDescriptorUrl = `${keycloakBaseUrl}/auth/realms/${keycloakAppName}`;

    const newConfig = {
        GuestAccountsSettings: {
            Enable: true,
        },
        SamlSettings: {
            Enable: true,
            EnableSyncWithLdap: false,
            EnableSyncWithLdapIncludeAuth: false,
            Verify: true,
            Encrypt: false,
            SignRequest: false,
            IdpUrl: idpUrl,
            IdpDescriptorUrl: idpDescriptorUrl,
            IdpMetadataUrl: '',
            ServiceProviderIdentifier: `${Cypress.config('baseUrl')}/login/sso/saml`,
            AssertionConsumerServiceURL: `${Cypress.config('baseUrl')}/login/sso/saml`,
            SignatureAlgorithm: 'RSAwithSHA256',
            CanonicalAlgorithm: 'Canonical1.0',
            IdpCertificateFile: 'saml-idp.crt',
            PublicCertificateFile: '',
            PrivateKeyFile: '',
            IdAttribute: 'username',
            GuestAttribute: '',
            EnableAdminAttribute: false,
            AdminAttribute: '',
            FirstNameAttribute: 'firstName',
            LastNameAttribute: 'lastName',
            EmailAttribute: 'email',
            UsernameAttribute: 'username',
            LoginButtonText: loginButtonText,
        },
    };

    let testSettings;

    before(() => {
        // * Check if server has license for SAML
        cy.apiRequireLicenseForFeature('SAML');

        // # Get certificates status and upload as necessary
        cy.apiGetSAMLCertificateStatus().then((resp) => {
            const data = resp.body;

            if (!data.idp_certificate_file) {
                cy.apiUploadSAMLIDPCert('saml-idp.crt');
            }
        });

        // # Update Configs
        cy.apiUpdateConfig(newConfig).then(({config}) => {
            cy.setTestSettings(loginButtonText, config).then((_response) => {
                testSettings = _response;
                cy.keycloakResetUsers({user1});
            });
        });
    });

    describe('SAML', () => {
        it('MM-T1423 - SAML Guest Setting disabled if Guest Access is turned off', () => {
            // # Visit saml settings
            cy.visit('/admin_console/authentication/saml');

            // # Turn on Guest Attribute Filter
            cy.findByTestId('SamlSettings.GuestAttributeinput').clear().type('username=e2etest.one');

            // # Save SAML Settings
            cy.findByText('Save').click().wait(TIMEOUTS.ONE_SEC);

            // # Visit guest access settings
            cy.visit('/admin_console/authentication/guest_access');

            // # Turn off Guest Access
            cy.findByTestId('GuestAccountsSettings.Enablefalse').check();

            // # Save Guest Account Settings
            cy.findByText('Save').click().wait(TIMEOUTS.ONE_SEC);

            // # Handle confirmation model
            cy.findByText('Save and Disable Guest Access').click().wait(TIMEOUTS.ONE_SEC);

            // # Visit saml settings
            cy.visit('/admin_console/authentication/saml');

            // * verify Guest Attribute is disabled.
            cy.findByTestId('SamlSettings.GuestAttributeinput').should('be.disabled');
        });

        it('MM-T1423 - SAML User will login as member', () => {
            testSettings.user = user1;

            // # MM Login via SAML
            cy.doSamlLogin(testSettings).then(() => {
                // # Login to Keycloak
                cy.doKeycloakLogin(testSettings.user).then(() => {
                    // # Create team if no membership
                    cy.skipOrCreateTeam(testSettings, getRandomId()).then(() => {
                        // * check the user is member, if can create public channel
                        cy.get('#createPublicChannel').should('exist');
                    });
                });
            });
        });

        it('MM-T1426 (Step 1) - User logged in as member, filter does not match', () => {
            const testConfig = {
                ...newConfig,
                GuestAccountsSettings: {
                    ...newConfig.GuestAccountSettings,
                    Enable: true,
                },
                SamlSettings: {
                    ...newConfig.SamlSettings,
                    GuestAttribute: 'username=Wrong',
                },
            };
            cy.apiAdminLogin().then(() => {
                cy.apiUpdateConfig(testConfig);
            });

            testSettings.user = user1;

            // # MM Login via SAML
            cy.doSamlLogin(testSettings).then(() => {
                // # Login to Keycloak
                cy.doKeycloakLogin(testSettings.user).then(() => {
                    // # Create team if no membership
                    cy.skipOrCreateTeam(testSettings, getRandomId()).then(() => {
                        // * check the user is member, if can create public channel
                        cy.get('#createPublicChannel').should('exist');
                    });
                });
            });
        });

        it('MM-T1426 (Step 2) - User logged in as guest, correct filter', () => {
            const testConfig = {
                ...newConfig,
                GuestAccountsSettings: {
                    ...newConfig.GuestAccountsSettings,
                    Enable: true,
                },
                SamlSettings: {
                    ...newConfig.SamlSettings,
                    GuestAttribute: userFilter,
                },
            };
            cy.apiAdminLogin().then(() => {
                cy.apiUpdateConfig(testConfig);
            });

            testSettings.user = user1;

            // # MM Login via SAML
            cy.doSamlLogin(testSettings).then(() => {
                // # Login to Keycloak
                cy.doKeycloakLogin(testSettings.user).then(() => {
                    // # Create team if no membership
                    cy.skipOrCreateTeam(testSettings, getRandomId()).then(() => {
                        // * check the user is member
                        cy.get('#createPublicChannel').should('not.exist');
                    });
                });
            });
        });
    });
});

