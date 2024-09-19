import requests
import json
import time
import sys
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import argparse
from requests.exceptions import HTTPError

def login_required(func):
    """
    Wrapper function that ensures a user is logged in and a token is set for the nessus API.
    """
    def wrapper(self, *args, **kwargs):
        if not hasattr(self, 'token') or self.token is None:
            raise AttributeError("Error: Not logged in.")
        return func(self, *args, **kwargs)
    return wrapper


class NessusAPI():
    """
    Class to interface with the nessus api
    """
    def __init__(self, url: str, username: str, password: str, verify: bool = False) -> None:
        self.url = url
        self.verify = verify
        self.username = username
        self.password = password
        self.token = self._login()

    def _login(self) -> str:
        """
        Login to nessus.
        """
        data = self.connect('POST', '/session', data={'username': self.username, 'password': self.password})
        if (token := data.get('token')):
            return token
        else:
            raise HTTPError("401: Bad Credentials")

    def logout(self) -> None:
        """
        Logout of nessus.
        """
        self.connect('DELETE', '/session')

    def build_url(self, resource) -> str:
        """
        Joins the Nessus Server URL with a resource URI
        """
        return f'{self.url}{resource}'


    @login_required
    def connect(self, method, resource, data=None) -> dict:
        """
        Send a request

        Send a request to Nessus based on the specified data. If the session token
        is available add it to the request. Specify the content type as JSON and
        convert the data to JSON format.
        """
        headers = {'X-Cookie': f'token={self.token}', 'content-type': 'application/json'}

        data = json.dumps(data)

        if method == 'POST':
            r = requests.post(self.build_url(resource), data=data, headers=headers, verify=verify)
        elif method == 'PUT':
            r = requests.put(self.build_url(resource), data=data, headers=headers, verify=verify)
        elif method == 'DELETE':
            r = requests.delete(self.build_url(resource), data=data, headers=headers, verify=verify)
        else:
            r = requests.get(self.build_url(resource), params=data, headers=headers, verify=verify)

        # Exit if there is an error.
        if r.status_code != 200:
            raise r.raise_for_status()

        # When downloading a scan we need the raw contents not the JSON data.
        if 'download' in resource:
            return r.content
        #if we destroy session, no json is given back
        elif method == 'DELETE' and 'session' in resource:
            return
        elif method == 'DELETE' and 'scans' in resource:
            return
        else:
            return r.json()

    @login_required
    def get_user_policies(self) -> dict:
        """
        Get scan policies

        Get all of the scan policies but return only the title and the uuid of
        each policy.
        """

        data = self.connect('GET', '/policies/')
        return dict((p['name'], p['template_uuid']) for p in data['policies'])

    @login_required
    def get_user_policy_ids(self) -> dict:
        """
        Get scan policies

        Get all of the scan policies but return only the title and the uuid of
        each policy.
        """

        data = self.connect('GET', '/policies/')
        return dict((p['template_uuid'],p['id']) for p in data['policies'])

    @login_required
    def get_system_policies(self) -> dict:
        """
        Get scan policies

        Get all of the scan policies but return only the title and the uuid of
        each policy.
        """

        data = self.connect('GET', '/editor/policy/templates')

        return dict((p['title'], p['uuid']) for p in data['templates'])


    @login_required
    def get_history_ids(self, sid) -> dict:
        """
        Get history ids

        Create a dictionary of scan uuids and history ids so we can lookup the
        history id by uuid.
        """
        data = self.connect('GET', '/scans/{0}'.format(sid))

        return dict((h['uuid'], h['history_id']) for h in data['history'])

    @login_required
    def get_scan_history(self, sid, hid) -> dict:
        """
        Scan history details

        Get the details of a particular run of a scan.
        """
        params = {'history_id': hid}
        data = self.connect('GET', '/scans/{0}'.format(sid), params)

        return data['info']

    @login_required
    def create_scan(self, name: str, desc: str, targets: str, pid: str, tid: str) -> str:
        """
        Add a new scan

        Create a new scan using the policy_id, name, description and targets. The
        scan will be created in the default folder for the user. Return the id of
        the newly created scan.
        """

        scan = {'uuid': pid,
                'settings': {
                    'name': name,
                    'description': desc,
                    'policy_id': tid,
                    'text_targets': targets}
                }

        data = self.connect('POST', '/scans', data=scan)
        return data['scan']

    @login_required
    def update_scan(self, scan_id: str, name: str, desc: str, targets: str, pid: str = None) -> dict:
        """
        Update a scan

        Update the name, description, targets, or policy of the specified scan. If
        the name and description are not set, then the policy name and description
        will be set to None after the update. In addition the targets value must
        be set or you will get an "Invalid 'targets' field" error.
        """

        scan = {}
        scan['settings'] = {}
        scan['settings']['name'] = name
        scan['settings']['desc'] = desc
        scan['settings']['text_targets'] = targets

        if pid is not None:
            scan['uuid'] = pid

        data = self.connect('PUT', '/scans/{0}'.format(scan_id), data=scan)

        return data

    @login_required
    def launch(self, sid: str) -> str:
        """
        Launch a scan

        Launch the scan specified by the sid.
        """

        data = self.connect('POST', '/scans/{0}/launch'.format(sid))

        return data['scan_uuid']

    @login_required
    def status(self, sid: str, hid: str) -> str|None:
        """
        Check the status of a scan run

        Get the historical information for the particular scan and hid. Return
        the status if available. If not return unknown.
        """

        d = self.get_scan_history(sid, hid)
        return d['status']

    @login_required
    def export_status(self, sid: str, fid: str) -> bool:
        """
        Check export status

        Check to see if the export is ready for download.
        """

        data = self.connect('GET', '/scans/{0}/export/{1}/status'.format(sid, fid))

        return data['status'] == 'ready'

    @login_required
    def create_export(self, sid: str, hid: str) -> str:
        """
        Make an export request

        Request an export of the scan results for the specified scan and
        historical run. In this case the format is hard coded as nessus but the
        format can be any one of nessus, html, pdf, csv, or db. Once the request
        is made, we have to wait for the export to be ready.
        """

        data = {'history_id': hid, 'format': 'nessus'}

        data = self.connect('POST', '/scans/{0}/export'.format(sid), data=data)

        fid = data['file']

        while export_status(sid, fid) is False:
            time.sleep(5)

        return fid


    @login_required
    def download_result(self, sid: str, fid: str, scanname: str, directory: str = ".") -> str:
        """
        Download the scan results

        Download the scan results stored in the export file specified by fid for
        the scan specified by sid.
        """
        data = self.connect('GET', '/scans/{0}/export/{1}/download'.format(sid, fid))
        filename = os.path.join(directory, scanname + '_nessus_{0}_{1}.nessus'.format(sid, fid))

        print('Saving scan results to {0}.'.format(filename))
        with open(filename, 'w') as f:
            f.write(data)

        return filename

    @login_required
    def delete(self, sid: str) -> None:
        """
        Delete a scan

        This deletes a scan and all of its associated history. The scan is not
        moved to the trash folder, it is deleted.
        """

        self.connect('DELETE', '/scans/{0}'.format(scan_id))


    @login_required
    def history_delete(self, sid: str, hid: str) -> None:
        """
        Delete a historical scan.

        This deletes a particular run of the scan and not the scan itself. the
        scan run is defined by the history id.
        """

        self.connect('DELETE', '/scans/{0}/history/{1}'.format(sid, hid))


if __name__ == '__main__':

    #check params
    parser = argparse.ArgumentParser()
    parser.add_argument("username", help="username to access nessus instance")
    parser.add_argument("username", help="password for user to access nessus instance")
    parser.add_argument("url", help="web url to access nessus instance")
    parser.add_argument("-target", help="comma delimited list of targets. Can be IP's or domainnames")
    parser.add_argument("-userpolicy", help="name of custom user policy")
    parser.add_argument("-listpolicies", help="list the names of all user defined policies", action="store_true")
    parser.add_argument("-scanname", help="name of the scan",default="nessuscli scan")
    parser.add_argument("-dontdeletescan",help="do not delete scan after done", action="store_true")
    args = parser.parse_args()

    nessusapi = NessusAPI(args.url, args.username, args.password)

    #check if policy from commandline exists
    udflist = nessusapi.get_user_policies()
    udf_id_list = nessusapi.get_user_policy_ids()

    if args.listpolicies:
        print("Available policies are:\n")
        for policy in udflist:
            print(policy)
        print("\n")
        sys.exit()

    try:
        policy_id = udflist[args.userpolicy]
        template_id = udf_id_list[policy_id]
    except KeyError:
        print("\n >>>> Can't find user policy with that name or id \nAvailable policies are:\n")
        for policy in udflist:
            print(policy)
        print("\n")
        sys.exit()

    print('Adding new scan.')

    scan_data = nessusapi.create_scan(args.scanname, 'Nessus CLI scan', args.target, policy_id, template_id)

    print('Starting the scan.')
    scan_id = scan_data['id']
    scan_uuid = nessusapi.launch(scan_id)

    #wait for scan to be completed
    history_ids = nessusapi.get_history_ids(scan_id)
    history_id = history_ids[scan_uuid]
    while nessusapi.status(scan_id, history_id) != 'completed':
        print("waiting...")
        time.sleep(30)

    print('Exporting the completed scan.')
    file_id = nessusapi.export(scan_id, history_id)
    nessusapi.download(scan_id, file_id, args.scanname)

    if  not args.dontdeletescan:
        print('Deleting the scan.')
        nessusapi.history_delete(scan_id, history_id)
        nessusapi.delete(scan_id)

    print('Logout')
    nessusapi.logout()

