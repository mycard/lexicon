from base import Provider as BaseProvider
import requests
import sys, os, base64, datetime, hashlib, hmac
#import json

class Provider(BaseProvider):

    def __init__(self, options, provider_options={}):
        super(Provider, self).__init__(options)
        self.domain_id = None
        self.api_endpoint = provider_options.get('api_endpoint') or 'https://route53.amazonaws.com//2013-04-01'

    def authenticate(self):

        payload = self._get('/hostedzonesbyname',{'dnsname': self.options['domain']})

        hosted_zones = payload.find('HostedZones').findall('HostedZone')
        if len(hosted_zones) > 1:
            raise StandardError('Too many domains found. This should not happen')
        #TODO: remove the /hostedzone/ prefix: https://docs.aws.amazon.com/Route53/latest/APIReference/api-list-hosted-zones-by-name.html#api-list-hosted-zones-by-name-request-name
        self.domain_id = hosted_zones[0].find('Id').text

    # Create record. If record already exists with the same content, do nothing'
    def create_record(self, type, name, content):
        record = {
            'type': type,
            'domain': self.domain_id,
            'host': self._relative_name(name),
            'ttl': 300,
            'prio': 0,
            'rdata': content
        }
        payload = {}
        try:
            payload = self._put('/zones/records/add/{0}/{1}'.format(self.domain_id, type), record)
        except requests.exceptions.HTTPError, e:
            if e.response.status_code == 400:
                payload = {}

                # http 400 is ok here, because the record probably already exists
        print 'create_record: {0}'.format(True)
        return True

    # List all records. Return an empty list if no records found
    # type, name and content are used to filter records.
    # If possible filter during the query, otherwise filter after response is received.
    def list_records(self, type=None, name=None, content=None):
        filter = {}

        payload = self._get('/zones/records/all/{0}'.format(self.domain_id))
        records = []
        for record in payload['data']:
            processed_record = {
                'type': record['type'],
                'name': "{0}.{1}".format(record['host'], record['domain']),
                'ttl': record['ttl'],
                'content': record['rdata'],
                'id': record['id']
            }
            records.append(processed_record)

        if type:
            records = [record for record in records if record['type'] == type]
        if name:
            records = [record for record in records if record['name'] == self._full_name(name)]
        if content:
            records = [record for record in records if record['content'] == content]

        print 'list_records: {0}'.format(records)
        return records

    # Create or update a record.
    def update_record(self, identifier, type=None, name=None, content=None):

        data = {
            'ttl': 300
        }
        if type:
            data['type'] = type
        if name:
            data['host'] = self._relative_name(name)
        if content:
            data['rdata'] = content

        payload = self._post('/zones/records/{0}'.format(identifier), data)

        print 'update_record: {0}'.format(True)
        return True

    # Delete an existing record.
    # If record does not exist, do nothing.
    def delete_record(self, identifier=None, type=None, name=None, content=None):
        if not identifier:
            records = self.list_records(type, name, content)
            print records
            if len(records) == 1:
                identifier = records[0]['id']
            else:
                raise StandardError('Record identifier could not be found.')
        payload = self._delete('/zones/records/{0}/{1}'.format(self.domain_id, identifier))

        # is always True at this point, if a non 200 response is returned an error is raised.
        print 'delete_record: {0}'.format(True)
        return True


    # Helpers
    def _request(self, action='GET',  url='/', data=None, query_params=None):
        if data is None:
            data = {}
        if query_params is None:
            query_params = {}

        default_headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }

        r = requests.request(action, self.api_endpoint + url, params=query_params,
                             data=json.dumps(data),
                             headers=default_headers)
        r.raise_for_status()  # if the request fails for any reason, throw an error.
        return r.json()

    # Key derivation functions. See:
    # http://docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html#signature-v4-examples-python
    # https://docs.aws.amazon.com/general/latest/gr/sigv4-signed-request-examples.html
    def sign(self, key, msg):
        return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

    def getSignatureKey(self, key, dateStamp, regionName, serviceName):
        kDate = self.sign(('AWS4' + key).encode('utf-8'), dateStamp)
        kRegion = self.sign(kDate, regionName)
        kService = self.sign(kRegion, serviceName)
        kSigning = self.sign(kService, 'aws4_request')
        return kSigning

    def getSignature(self, uri, headers, data, query_params):
        # ************* TASK 1: CREATE A CANONICAL REQUEST *************
        # http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html

        # Step 1 is to define the verb (GET, POST, etc.)--already done.

        # Step 2: Create canonical URI--the part of the URI from domain to query
        # string (use '/' if no path)
        canonical_uri = uri

        # Step 3: Create the canonical query string. In this example (a GET request),
        # request parameters are in the query string. Query string values must
        # be URL-encoded (space=%20). The parameters must be sorted by name.
        # For this example, the query string is pre-formatted in the request_parameters variable.
        canonical_querystring = request_parameters