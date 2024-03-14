// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Amplify } from '@aws-amplify/core';
import {
	AuthAction,
	HubInternal,
	assertTokenProviderConfig,
} from '@aws-amplify/core/internals/utils';

import { ConfirmSignUpInput, ConfirmSignUpOutput, SignInInput } from '../types';
import { assertValidationError } from '../../../errors/utils/assertValidationError';
import { AuthValidationErrorCode } from '../../../errors/types/validation';
import { ConfirmSignUpException } from '../types/errors';
import { confirmSignUp as confirmSignUpClient } from '../utils/clients/CognitoIdentityProvider';
import { getRegion } from '../utils/clients/CognitoIdentityProvider/utils';
import { AutoSignInEventData } from '../types/models';
import {
	autoSignInUserConfirmed,
	isAutoSignInStarted,
	isAutoSignInUserUsingConfirmSignUp,
	setAutoSignInStarted,
	setUsernameUsedForAutoSignIn,
} from '../utils/signUpHelpers';
import { getAuthUserAgentValue } from '../../../utils';
import { getUserContextData } from '../utils/userContextData';

import { setAutoSignIn } from './autoSignIn';

/**
 * Confirms a new user account.
 *
 * @param input -  The ConfirmSignUpInput object.
 * @returns ConfirmSignUpOutput
 * @throws -{@link ConfirmSignUpException }
 * Thrown due to an invalid confirmation code.
 * @throws -{@link AuthValidationErrorCode }
 * Thrown due to an empty confirmation code
 * @throws AuthTokenConfigException - Thrown when the token provider config is invalid.
 */
export async function confirmSignUp(
	input: ConfirmSignUpInput,
): Promise<ConfirmSignUpOutput> {
	const { username, confirmationCode, options } = input;

	const authConfig = Amplify.getConfig().Auth?.Cognito;
	assertTokenProviderConfig(authConfig);
	const { userPoolId, userPoolClientId } = authConfig;
	const clientMetadata = options?.clientMetadata;
	assertValidationError(
		!!username,
		AuthValidationErrorCode.EmptyConfirmSignUpUsername,
	);
	assertValidationError(
		!!confirmationCode,
		AuthValidationErrorCode.EmptyConfirmSignUpCode,
	);

	const signInServiceOptions =
		typeof options?.autoSignIn !== 'boolean' ? options?.autoSignIn : undefined;

	const signInInput: SignInInput = {
		username,
		options: signInServiceOptions,
	};
	// if the authFlowType is 'CUSTOM_WITHOUT_SRP' then we don't include the password
	if (!isAutoSignInStarted()) {
		if (signInServiceOptions?.authFlowType !== 'CUSTOM_WITHOUT_SRP') {
			throw new Error(
				'Only CUSTOM_WITHOUT_SRP is supported for authFlowType in signInServiceOptions.',
			);
		}

		if (signInServiceOptions || options?.autoSignIn === true) {
			setUsernameUsedForAutoSignIn(username);
			setAutoSignInStarted(true);
			setAutoSignIn(autoSignInUserConfirmed(signInInput));
		}
	}

	const UserContextData = getUserContextData({
		username,
		userPoolId,
		userPoolClientId,
	});

	await confirmSignUpClient(
		{
			region: getRegion(authConfig.userPoolId),
			userAgentValue: getAuthUserAgentValue(AuthAction.ConfirmSignUp),
		},
		{
			Username: username,
			ConfirmationCode: confirmationCode,
			ClientMetadata: clientMetadata,
			ForceAliasCreation: options?.forceAliasCreation,
			ClientId: authConfig.userPoolClientId,
			UserContextData,
		},
	);

	return new Promise((resolve, reject) => {
		try {
			const signUpOut: ConfirmSignUpOutput = {
				isSignUpComplete: true,
				nextStep: {
					signUpStep: 'DONE',
				},
			};

			if (
				!isAutoSignInStarted() ||
				!isAutoSignInUserUsingConfirmSignUp(username)
			) {
				resolve(signUpOut);

				return;
			}

			const stopListener = HubInternal.listen<AutoSignInEventData>(
				'auth-internal',
				({ payload }) => {
					switch (payload.event) {
						case 'autoSignIn':
							resolve({
								isSignUpComplete: true,
								nextStep: {
									signUpStep: 'COMPLETE_AUTO_SIGN_IN',
								},
							});
							setAutoSignInStarted(false);
							stopListener();
					}
				},
			);

			HubInternal.dispatch('auth-internal', {
				event: 'confirmSignUp',
				data: signUpOut,
			});
		} catch (error) {
			reject(error);
		}
	});
}
