import os
import re
import saml2
import saml2.saml

from saml.models import SAMLConfiguration


# This config loader works with one Azure AD and one OneLogin application
# with the following SAMLConfiguration db models:
#
# Project: microsoft
# Entity id: https://login.microsoftonline.com/c0b91d10-3235-4bb7-9d95-4225d0b76405/federationmetadata/2007-06/federationmetadata.xml?appid=1cf0fd7e-84c6-48b3-acfc-acfc702cb1f3
#
# Project: onelogin
# Entity id: https://app.onelogin.com/saml/metadata/1671a9b1-a436-46b4-a88c-d546bf29b263
#
# They match users charlie.garrett@gmail.com and cdgarrett@maryalicegarrett.com
# respectively.

def LoadSamlConfig(request):
    print('Load SAML config for request:', request)

    project_name = None
    project_re = re.compile('^/polls/\?project=(\w+)$')
    if request.method == 'GET':
        # print('GET args:', request.GET.dict)
        if 'next' in request.GET:
            next_arg = request.GET['next']
            project_match = re.match(project_re, next_arg)
            if project_match:
                project_name = project_match.group(1)
    elif request.method == 'POST':
        # print('POST args:', request.POST.dict)
        if 'RelayState' in request.POST:
            relay_arg = request.POST['RelayState']
            project_match = re.match(project_re, relay_arg)
            if project_match:
                project_name = project_match.group(1)

    try:
        saml_db_obj = SAMLConfiguration.objects.get(project=project_name)
    except SAMLConfiguration.DoesNotExist:
        saml_db_obj = None

    if saml_db_obj is None:
        return None

    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    saml_config = {
        # full path to the xmlsec1 binary programm
        'xmlsec_binary': '/usr/local/bin/xmlsec1',

        # your entity id, usually your subdomain plus the url to the metadata view
        'entityid': 'https://localhost:8080/saml2/metadata/',

        # directory with attribute mapping
        'attribute_map_dir': os.path.join(base_dir, 'attributemaps'),

        # this block states what services we provide
        'service': {
            # we are just a lonely SP
            'sp' : {
                'name': 'Federated Django sample SP',
                'name_id_format': saml2.saml.NAMEID_FORMAT_EMAILADDRESS,
                'allow_unsolicited' : True,
                'endpoints': {
                    # url and binding to the assertion consumer service view
                    # do not change the binding or service name
                    'assertion_consumer_service': [
                        ('https://localhost:8080/saml2/acs/',
                         saml2.BINDING_HTTP_POST),
                    ],
                    # url and binding to the single logout service view
                    # do not change the binding or service name
                    'single_logout_service': [
                        ('https://localhost:8080/saml2/ls/',
                         saml2.BINDING_HTTP_REDIRECT),
                        ('https://localhost:8080/saml2/ls/post',
                         saml2.BINDING_HTTP_POST),
                    ],
                },
                # Mandates that the identity provider MUST authenticate the
                # presenter directly rather than rely on a previous security context.
                'force_authn': False,

                # Enable AllowCreate in NameIDPolicy.
                'name_id_format_allow_create': False,

                # attributes that this project need to identify a user
                'required_attributes': ['uid'],

                # attributes that may be useful to have but not required
                'optional_attributes': ['eduPersonAffiliation'],
            },
        },

        # where the remote metadata is stored
        'metadata': {
            'remote': [{
                'url': saml_db_obj.entity_id
                # 'cert': os.path.join(base_dir, 'onelogin.cert'),
            }]
        },

        # set to 1 to output debugging information
        'debug': 1,

        # Signing
        'key_file': os.path.join(base_dir, 'keys/mycert.key'),  # private part
        'cert_file': os.path.join(base_dir, 'keys/mycert.cert'),  # public part

        # Encryption
        'encryption_keypairs': [{
            'key_file': os.path.join(base_dir, 'keys/my_encryption_key.key'),  # private part
            'cert_file': os.path.join(base_dir, 'keys/my_encryption_key.cert'),  # public part
        }],

        # own metadata settings
        'contact_person': [
            {'given_name': 'Charlie',
             'sur_name': 'Garrett',
             'company': 'None',
             'email_address': 'charlie.garrett@gmail.com',
             'contact_type': 'technical'},
        ],
        # you can set multilanguage information here
        'organization': {
            'name': [('Me', 'en')],
            'display_name': [('Charlie', 'en')],
            'url': [('https://localhost:8080', 'en')],
        },
        'valid_for': 24,  # how long is our metadata valid

        # Library does not know about attributes for microsoft claims
        'allow_unknown_attributes': True
        # TODO(Charlie): Probably have to change attribute mappings.
    }

    return saml2.config.config_factory('dict', saml_config)
