//Site configuration.
//jsolveClientId: the application (client) id of the multi-tenant app registration JSolve B.V. publishes for this site.
//Leave it empty on a copy you host yourself: visitors then sign in with their own app registration, which the page
//asks for (New-AzCmplyAppRegistration.ps1 creates one).
export default {
    jsolveClientId: 'bb0c5b66-1fb5-4f8e-94de-dce32779b694',
    defaultTenant: 'organizations',
    defaultCloud: 'AzureCloud',
    documentation: 'https://github.com/jflieben/AzCmply#readme'
};
