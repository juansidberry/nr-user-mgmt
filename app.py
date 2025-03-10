from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
import requests
import os
import json
# from dotenv import load_dotenv


# Load environment variables from .env file
# load_dotenv(override=True)

akv_url = 'https://sandbox-eus-kv-sre-001.vault.azure.net/'
credential = DefaultAzureCredential()
akv_client = SecretClient(vault_url=akv_url, credential=credential)
nr_sso_group_id = akv_client.get_secret("new-relic-sso-group-id")
api_key = akv_client.get_secret("newrelic-license-key")

# api_key = os.getenv('NR_API_KEY')

do_not_delete = ["thielman@sggtech.com","test.user1@insightglobal.com","newrelic.svc@insightglobal.com"]

header = """
*********************************************
*                                           *
*  the following names are not in Azure AD  *
*                                           *
*********************************************
"""

def get_users_from_azure():
    # Create a credential object using the DefaultAzureCredential class
    credential    = DefaultAzureCredential()
    group_id      = nr_sso_group_id
    ms_graph_base = "https://graph.microsoft.com"
    default_url   = f"{ms_graph_base}/.default"
    url           = f"{ms_graph_base}/v1.0/groups/{group_id}/members"

    # Acquire token for Microsoft Graph
    token_response = credential.get_token(default_url)

    # set up header with access token
    headers = {
        'Authorization': 'Bearer ' + token_response.token,
        'Content-Type': 'application/json'
    }

    names = []

    while url:
        # Grab the list of users from Azure
        resp = requests.get(url, headers=headers)
        data = resp.json()
        names.extend([item['mail'].lower() for item in data['value']])
        url = data.get('@odata.nextLink')  # Get the URL for the next page of results

    return names


def get_users_from_new_relic(api_key):
    results = []
    url     = 'https://api.newrelic.com/graphql'  # Endpoint for fetching users
    headers = {
        "Api-Key": api_key,
        "Content-Type": "application/json"
    }

    # Define the GraphQL query
    query = """
    {
      actor {
        organization {
          userManagement {
            authenticationDomains(id: "6e2749c6-e744-4bc8-b30e-587ec574aca7") {
              authenticationDomains {
                users {
                  users {
                    id
                    email
                  }
                }
              }
            }
          }
        }
      }
    }
    """

    # Make the request
    response = requests.post(url, headers=headers, json={'query': query})

    if response.status_code == 200:
        # Parse the response JSON and extract the user data
        data = json.loads(json.dumps(response.json()))

        user_data = data['data']['actor']['organization']['userManagement']['authenticationDomains']['authenticationDomains'][0]['users']['users']

        for user in user_data:
            if user['email'] in do_not_delete:
                pass
            else:
                results.append(user)

        return results
    else:
        print("Failed to fetch users:", response.status_code, response.text)
        return None


def create_user_remove_list(azure_response, new_relic_users):
    # print the user names and emails addresses
    if new_relic_users is not None:
        nr_emails = {user['email'].lower() for user in new_relic_users}

    # Convert the sets to lists
    list_nr = list(nr_emails)
    list_az = list(azure_response)

    list_nr.sort()
    list_az.sort()

    nr_not_az = [item for item in list_nr if item not in list_az]

    return nr_not_az


def rm_user_from_nr(api_key, user_id):
    url     = 'https://api.newrelic.com/graphql'  # Endpoint for fetching users
    headers = {
        "Api-Key": api_key,
        "Content-Type": "application/json"
    }

    # Define the GraphQL query
    mutation = f"""
    mutation {{
      userManagementDeleteUser(deleteUserOptions: {{id: "{user_id}"}}) {{
        deletedUser {{
          id
        }}
      }}
    }}
    """

    # Make the request
    response = requests.post(url, headers=headers, data=json.dumps({"query": mutation}))

    if response.status_code == 200:
        print(response.text)
    else:
        print("Failed to fetch users:", response.status_code, response.text)
        return None
    

def remove_users_from_new_relic(user_remove_list, new_relic_users):
    # loop through the Remove User list and find the matching New Rlic user ID
    # and delete the user from New Relic
    for rm_user in user_remove_list:
        for new_relic_user in new_relic_users:
            if rm_user == new_relic_user['email'].lower():
                print(f"{new_relic_user['id']}\t{new_relic_user['email']}\n          \t{rm_user}\n")
                # actually delete a user from New Relic
                rm_user_from_nr(api_key, new_relic_user['id'])

def main():
    # gets a list of users from Entra ID
    azure_user_list  = get_users_from_azure()

    # get a list of users from New Relic
    new_relic_users  = get_users_from_new_relic(api_key)

    # creats a list of users to be deleted from New Relic based on list in Entra ID
    user_remove_list = create_user_remove_list(azure_user_list, new_relic_users)

    if user_remove_list:
        print(f"\n\tThese are the users who will be removed from New Relic:\n")
        for nr_user_name in user_remove_list:
            print(f"\t\t{nr_user_name}")
        while True:
            choice = input(f"\n\tDo you want to continue? (y/N): ").strip().lower()
            if choice == 'y':
                # actually removes users from New Relic
                remove_users_from_new_relic(user_remove_list, new_relic_users)
            elif choice == 'n' or choice == '':
                print("You chose to exit.")
                break
            else:
                print("Invalid input. Please enter 'y' to continue or 'N' to exit.")
    else:
        print(f"\n\tThere are no users to remove\n")


if __name__ == '__main__':
    main()




