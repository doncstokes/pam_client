// File: pam_client.c
// Author: Don Stokes <don@donstokes.com>
// Purpose:
//   Simple example to determine authentic username and password.
// Usage:
//   Argument 1 - username
// Compile Command:
//   gcc -o pam_client pam_client.c -lpam -lpam_misc
// Notes:
//   IMPORTANT! IMPORTANT! IMPORTANT!
//   Executing user must have access to /etc/shadow or failure results.
//   To do this, add executing user to shadow group in /etc/group

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_appl.h>

// Purpose:
//   Callback function for PAM to acquire password.
//   I have not seen it do anything else with it since we provide username.
static int pamConversation(
	int msgCnt,                       // Number of requests in array
	const struct pam_message **ppMsg, // Array of pointers to requests
	struct pam_response **ppResp,   // Pointer to Array pointer (output)
	void *appdata_ptr                 // Context data passed to pam_start()
) {
	int status = PAM_SUCCESS;
	// Calculate memory size for array of responses
	int memSize = sizeof(struct pam_response) * msgCnt;
	// Allocate heap memory for response array
	struct pam_response * responses = malloc(memSize);
	// Clear the memory for grins/giggles
	memset(responses, 0, memSize);
	// Provide the array to the caller
	*ppResp = responses;
	// Execute each request of array from PAM
	for (int i = 0; i < msgCnt; i++) {
		switch (ppMsg[i]->msg_style) {
		 case PAM_PROMPT_ECHO_OFF:
		 case PAM_PROMPT_ECHO_ON:
		 	// Display PAM prompt to the user
		 	fprintf(stdout, "%s ", ppMsg[i]->msg);
		 	fflush(stdout);
		 	// Read input from user for PAM
			char buf[128];
			fgets(buf, sizeof(buf), stdin);
			// Strip off newline read from input
			char * pnl = strchr(buf, '\n');
			if (pnl) *pnl = 0;
			// Allocate copy of string from heap
			responses[i].resp = strdup(buf);
			responses[i].resp_retcode = PAM_SUCCESS;
			break;
			
		 case PAM_ERROR_MSG:
		 	fprintf(stderr, "%s ", ppMsg[i]->msg);
		 	fflush(stderr);
		 	break;
		 	
		 case PAM_TEXT_INFO:
		 	fprintf(stdout, "%s ", ppMsg[i]->msg);
		 	fflush(stdout);
		 	break;
		}
	}
	return status;
}

// Purpose:
//   Entry point of program.
//   Command line argument is username to authenticate.
//   Returns PAM status code or 20 if no input argument.
//     PAM status code 0 means success
//     PAM status code 7 means failure (typically bad credentials)
int main(int argc, char * argv[]) {
	int exitCode = 0;
	int status = 0;  // Status from PAM
	
	if (argc > 1) { // Check for required command line argument
		pam_handle_t *hPam = NULL;
		struct pam_conv pamConv = {pamConversation, NULL}; // PAM Callback function, context data
		// Use "login" config file at /etc/pam.d/login
		status = pam_start("login", argv[1], &pamConv, &hPam); // Pass config, username, callback, ptr to receive handle
		fprintf(stderr, "pam_start() = %d\n", status);
		status = pam_authenticate(hPam, 0);
		fprintf(stderr, "pam_authenticate() = %d\n", status);
		pam_end(hPam, status);
		exitCode = status;
	} else {
		// Missing required command line argument
		fprintf(stderr, "Usage: %s username\n", argv[0]);
		exitCode = 20;
	}
	
	return exitCode;
}
