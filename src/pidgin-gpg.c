/*                
 * Pidgin - GPG Pidgin Plugin
 *                                
 * Copyright (C) 2010, Aerol <rectifier04@gmail.com>
 *                     Alexander Murauer <segler_alex@web.de>
 *                                                                 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#define PURPLE_PLUGINS

#ifndef TRUE
	#define TRUE		(1==1)
#endif
#ifndef FALSE
	#define FALSE		(1==0)
#endif

#define PLUGIN_ID		"core-segler-pidgin-gpg"
#define PREF_ROOT		"/plugins/core/core-segler-pidgin-gpg"
#define PREF_MY_KEY		"/plugins/core/core-segler-pidgin-gpg/my_key_fpr"

#include				"../config.h"

#include				<locale.h>
#include				<string.h>

#include				"notify.h"
#include				"plugin.h"
#include				"version.h"

#include				<pluginpref.h>
#include				<prefs.h>
#include				<debug.h>

#include				<gpgme.h>

static GHashTable*		list_fingerprints = NULL;

static const char*		NS_SIGNED		= "jabber:x:signed";
static const char*		NS_ENC			= "jabber:x:encrypted";
static const char*		NS_XMPP_CARBONS	= "urn:xmpp:carbons:2";
static const char*		PGP_MSG_HEADER	= "-----BEGIN PGP MESSAGE-----\n\n";
static const char*		PGP_MSG_FOOTER	= "\n-----END PGP MESSAGE-----";
static const char*		PGP_SIG_HEADER	= "-----BEGIN PGP SIGNATURE-----\n\n";
static const char*		PGP_SIG_FOOTER	= "\n-----END PGP SIGNATURE-----";

/* ------------------
 * internal item definition for list_fingerprints
 * ------------------ */
struct list_item {
	// the gpgme context to reuse
	gpgme_ctx_t				ctx;
	// the gpgme key array with the fpr and senders fpr within ctx
	gpgme_key_t				key_arr[ 3 ];
	// the key-fingerprint of the receiver
	char*					fpr;
	// true if connection mode is encrypted
	int						mode_sec;
	// old mode_sec value, used to check if user has already been informed on possible mode_sec change
	int						mode_sec_old;
};

/* ------------------
 * called upon destruction of a list_item
 * ------------------ */
static void list_item_destroy( gpointer item ) {
	if( item == NULL )
		return;

	// free all resources
	if( ( (struct list_item*)item )->key_arr[ 0 ] != NULL )
		gpgme_key_release( ( (struct list_item*)item )->key_arr[ 0 ] );
	if( ( (struct list_item*)item )->key_arr[ 1 ] != NULL )
		gpgme_key_release( ( (struct list_item*)item )->key_arr[ 1 ] );
	if( ( (struct list_item*)item )->ctx != NULL )
		gpgme_release( ( (struct list_item*)item )->ctx );
	if( ( (struct list_item*)item )->fpr != NULL )
		g_free( ( (struct list_item*)item )->fpr );
	g_free( item );
}

/* ------------------
 * xmlnode.h lacks a method for clearing the data of a node
 * ------------------ */
void xmlnode_clear_data( xmlnode *node ) {
	g_return_if_fail( node != NULL );

	xmlnode					*data_node, *sibling = NULL;

	data_node = node->child;
	while( data_node ) {
		if( data_node->type == XMLNODE_TYPE_DATA ) {
			if( node->lastchild == data_node ) {
				node->lastchild = sibling;
			}
			if( sibling == NULL ) {
				node->child = data_node->next;
				xmlnode_free( data_node );
				data_node = node->child;
			} else {
				sibling->next = data_node->next;
				xmlnode_free( data_node );
				data_node = sibling->next;
			}
		} else {
			sibling = data_node;
			data_node = data_node->next;
		}
	}
}

/* ------------------
 * wrap an ASCII string with PGP header/footer
 * FREE MEMORY AFTER USAGE OF RETURN VALUE!
 * ------------------ */
static char* str_pgp_wrap( const char* unwrappedBuffer, gboolean asSignature ) {
	if( unwrappedBuffer == NULL ) {
		purple_debug_error( PLUGIN_ID, "str_pgp_wrap: missing unwrappedBuffer\n" );
		return NULL;
	}

	char*					buffer = NULL;
	
	if( asSignature ) {
		if( ( buffer = g_malloc( strlen( PGP_SIG_HEADER ) + strlen( unwrappedBuffer ) + strlen( PGP_SIG_FOOTER ) + 1 ) ) != NULL ) {
			strcpy( buffer, PGP_SIG_HEADER );
			strcat( buffer, unwrappedBuffer );
			strcat( buffer, PGP_SIG_FOOTER );
		}
	} else {
		if( ( buffer = g_malloc( strlen( PGP_MSG_HEADER ) + strlen( unwrappedBuffer ) + strlen( PGP_MSG_FOOTER ) + 1 ) ) != NULL ) {
			strcpy( buffer, PGP_MSG_HEADER );
			strcat( buffer, unwrappedBuffer );
			strcat( buffer, PGP_MSG_FOOTER );
		}
	}

	return buffer;
}

/* ------------------
 * unwrap an ASCII string with PGP header/footer and additional infos to get the pure cypher block
 * FREE MEMORY AFTER USAGE OF RETURN VALUE!
 * ------------------ */
static char* str_pgp_unwrap( const char* wrappedBuffer ) {
	if( wrappedBuffer == NULL ) {
		purple_debug_error( PLUGIN_ID, "str_pgp_unwrap: missing wrappedBuffer\n" );
		return NULL;
	}

	const char*				header = PGP_MSG_HEADER;
	const char*				footer = PGP_MSG_FOOTER;
	const char				*begin, *end, *tmp;
	char*					buffer = NULL;
	unsigned				bufferIndex = 0;

	begin = end = (char*)wrappedBuffer;
	if( begin == NULL )
		return NULL;

	// Search for the message header
	if( ( tmp = strstr( begin, header ) ) != NULL )
		begin == tmp;
	// Search for the signature header
	else if( ( begin = strstr( begin, PGP_SIG_HEADER ) ) != NULL ) {
		header = PGP_SIG_HEADER;
		footer = PGP_SIG_FOOTER;
	} else
		return NULL;
	// Skip the header
	begin += strlen( header ) * sizeof( char );
	// Search the footer
	if( ( end = strstr( begin, footer ) ) == NULL )
		return NULL;
	// Skip newline chars before the footer
	while( *( end - 1 * sizeof( char ) ) == '\r' || *( end - 1 * sizeof( char ) ) == '\n' )
		end -= sizeof( char );
	if( end <= begin )
		return NULL;
	// Skip until the last occurance of an empty line before the end
	while( ( tmp = strstr( begin, "\n\n" ) ) != NULL && tmp < end )
		begin = tmp + 2 * sizeof( char );
	while( ( tmp = strstr( begin, "\r\n\r\n" ) ) != NULL && tmp < end )
		begin = tmp + 4 * sizeof( char );
	if( end <= begin )
		return NULL;

	// Copy the unwrapped cypher block, without any newline chars
	buffer = (char*)g_malloc( ( end - begin + 1 ) * sizeof( char ) );
	while( begin < end ) {
		if( *begin != '\r' && *begin != '\n' )
			buffer[ bufferIndex++ ] = *begin;
		begin++;
	}
	buffer[ bufferIndex ] = 0;

	return buffer;
}

/* ------------------
 * strips resource info from jid
 * FREE MEMORY AFTER USAGE OF RETURN VALUE!
 * ------------------ */
static char* get_bare_jid( const char* jid ) {
	if( jid == NULL ) {
		purple_debug_error( PLUGIN_ID, "get_bare_jid: missing jid\n" );
		return NULL;
	}

	int						len = strcspn( jid, "/" );
	char*					str = NULL;

	if( len > 0 && ( str = g_malloc( len + 1 ) ) != NULL ) {
		strncpy( str, jid, len );
		str[ len ] = 0;
	}
	return str;
}

/* ------------------
 * check if a key is locally available
 * ------------------ */
int is_key_available( gpgme_ctx_t* ctx, gpgme_key_t* key_arr, const char* fpr, int secret, int servermode, char** userid ) {
	if( ctx == NULL ) {
		purple_debug_error( PLUGIN_ID, "is_key_available: missing ctx\n" );
		return FALSE;
	}
	if( key_arr == NULL ) {
		purple_debug_error( PLUGIN_ID, "is_key_available: missing key_arr\n" );
		return FALSE;
	}
	if( fpr == NULL ) {
		purple_debug_error( PLUGIN_ID, "is_key_available: missing fpr\n" );
		return FALSE;
	}

	gpgme_error_t			error;
	gpgme_keylist_mode_t	current_keylist_mode;

	// connect to gpgme if no context is given to reuse
	if( *ctx == NULL ) {
		gpgme_check_version( NULL );
		error = gpgme_new( ctx );
		if( error ){
			purple_debug_error( PLUGIN_ID, "gpgme_new failed: %s %s\n", gpgme_strsource( error ), gpgme_strerror( error ) );
			return FALSE;
		}
	}

	// if there is no key yet
	if( key_arr[ 0 ] == NULL ) {
		// set to server search mode if servermode == TRUE
		if( servermode == TRUE ) {
			purple_debug_info( PLUGIN_ID, "set keylist mode to server\n" );
			current_keylist_mode = gpgme_get_keylist_mode( *ctx );
			gpgme_set_keylist_mode( *ctx, ( current_keylist_mode | GPGME_KEYLIST_MODE_EXTERN ) & ( ~GPGME_KEYLIST_MODE_LOCAL ) );
		}

		// get key by fingerprint
		error = gpgme_get_key( *ctx, fpr, &key_arr[ 0 ], secret );
		if( error || key_arr[ 0 ] == NULL ) {
			purple_debug_error( PLUGIN_ID, "gpgme_get_key failed: %s %s\n", gpgme_strsource( error ), gpgme_strerror( error ) );
			return FALSE;
		}

		// in server mode
		if( servermode == TRUE ) {
			// unset server search mode
			purple_debug_info( PLUGIN_ID, "set keylist mode to server\n" );
			current_keylist_mode = gpgme_get_keylist_mode( *ctx );
			gpgme_set_keylist_mode( *ctx, ( current_keylist_mode | GPGME_KEYLIST_MODE_LOCAL ) & ( ~GPGME_KEYLIST_MODE_EXTERN ) );

			// import the key
			error = gpgme_op_import_keys( *ctx, key_arr );
			if( error ) {
				purple_debug_error( PLUGIN_ID, "gpgme_op_import_keys failed: %s %s\n", gpgme_strsource( error ), gpgme_strerror( error ) );
				return FALSE;
			}
		}
	}

	// if we have parameter, tell caller about userid
	if( userid != NULL ) {
		*userid = g_strdup( key_arr[ 0 ]->uids->uid );
	}

	return TRUE;
}

/* ------------------
 * get ascii armored public key
 * FREE MEMORY AFTER USAGE OF RETURN VALUE!
 * ------------------ */
char* get_key_armored( const char* fpr ) {
	if( fpr == NULL ) {
		purple_debug_error( PLUGIN_ID, "get_key_armored: missing fpr\n" );
		return NULL;
	}

	gpgme_error_t			error;
	gpgme_ctx_t				ctx;
	gpgme_data_t			key_data;
	gpgme_key_t				key_arr[ 2 ];
	size_t					len = 0;
	char*					key_str = NULL;
	char*					key_str_dup = NULL;

	key_arr[ 0 ] = key_arr[ 1 ] = NULL;

	// connect to gpgme
	gpgme_check_version( NULL );
	error = gpgme_new( &ctx );
	if( error ) {
		purple_debug_error( PLUGIN_ID, "gpgme_new failed: %s %s\n", gpgme_strsource( error ), gpgme_strerror( error ) );
		return NULL;
	}

	// get key by fingerprint
	error = gpgme_get_key( ctx, fpr, &key_arr[ 0 ], 0 );
	if( error || key_arr[ 0 ] == NULL ) {
		purple_debug_error( PLUGIN_ID, "gpgme_get_key failed: %s %s\n", gpgme_strsource( error ), gpgme_strerror( error ) );
		gpgme_release( ctx );
		return NULL;
	}

	// create data containers
	error = gpgme_data_new( &key_data );
	if( error ) {
		purple_debug_error( PLUGIN_ID, "gpgme_data_new failed: %s %s\n", gpgme_strsource( error ), gpgme_strerror( error ) );
		gpgme_key_release( key_arr[ 0 ] );
		gpgme_release( ctx );
		return NULL;
	}

	// export key
	gpgme_set_armor( ctx, 1 );
	error = gpgme_op_export_keys( ctx, key_arr, 0, key_data );
	if( error ) {
		purple_debug_error( PLUGIN_ID, "gpgme_op_export_keys failed: %s %s\n", gpgme_strsource( error ), gpgme_strerror( error ) );
		gpgme_data_release( key_data );
		gpgme_key_release( key_arr[ 0 ] );
		gpgme_release( ctx );
		return NULL;
	}

	// release memory for data containers
	key_str = gpgme_data_release_and_get_mem( key_data, &len );
	if( key_str != NULL ) {
		if( len > 0 && ( key_str_dup = g_malloc( len + 1 ) ) != NULL ) {
			strncpy( key_str_dup, key_str, len );
			key_str_dup[ len ] = 0;
		}
		gpgme_free( key_str );
	}

	// release resources
	gpgme_key_release( key_arr[ 0 ] );
	gpgme_release( ctx );

	// we got the key, YEAH :)
	return key_str_dup;
}

/* ------------------
 * import ascii armored key
 * ------------------ */
int import_key( char* armored_key ) {
	if( armored_key == NULL ) {
		purple_debug_error( PLUGIN_ID, "import_key: missing armored_key\n" );
		return FALSE;
	}

	gpgme_error_t			error;
	gpgme_ctx_t				ctx;
	gpgme_data_t			keydata;
	gpgme_import_result_t	result;

	// connect to gpgme
	gpgme_check_version( NULL );
	error = gpgme_new( &ctx );
	if( error ) {
		purple_debug_error( PLUGIN_ID, "gpgme_new failed: %s %s\n", gpgme_strsource( error ), gpgme_strerror( error ) );
		return FALSE;
	}

	purple_debug_info( PLUGIN_ID, "try to import key: %s\n", armored_key );
	// create data containers
	error = gpgme_data_new_from_mem( &keydata, armored_key, strlen( armored_key ), 1 );
	if( error ) {
		purple_debug_error( PLUGIN_ID, "gpgme_data_new_from_mem failed: %s %s\n", gpgme_strsource( error ), gpgme_strerror( error ) );
		gpgme_release( ctx );
		return FALSE;
	}

	// import key, ascii armored
	gpgme_set_armor( ctx, 1 );
	error =  gpgme_op_import( ctx, keydata );
	if( error ) {
		purple_debug_error( PLUGIN_ID, "gpgme_op_import: %s %s\n", gpgme_strsource( error ), gpgme_strerror( error ) );
		gpgme_data_release( keydata );
		gpgme_release( ctx );
		return FALSE;
	}

	result = gpgme_op_import_result( ctx );
	purple_debug_info( PLUGIN_ID, "considered keys: %d; imported keys: %d; not imported keys: %d\n", result->considered, result->imported, result->not_imported );

	// release resources
	gpgme_data_release( keydata );
	gpgme_release( ctx );

	return TRUE;
}

/* ------------------
 * sign a plain string with the key found with fingerprint fpr
 * FREE MEMORY AFTER USAGE OF RETURN VALUE!
 * ------------------ */
static char* sign( const char* plain_str, const char* fpr ) {
	if( plain_str == NULL ) {
		purple_debug_error( PLUGIN_ID, "sign: missing plain_str\n" );
		return NULL;
	}
	if( fpr == NULL ) {
		purple_debug_error( PLUGIN_ID, "sign: missing fpr\n" );
		return NULL;
	}

	gpgme_error_t			error;
	gpgme_ctx_t				ctx;
	gpgme_key_t				key;
	gpgme_data_t			plain, sig;
	const int				MAX_LEN = 10000;
	char					*sig_str, *sig_str_tmp, *sig_str_dup = NULL;
	size_t					len = 0;

	// connect to gpgme
	gpgme_check_version( NULL );
	error = gpgme_new( &ctx );
	if( error ) {
		purple_debug_error( PLUGIN_ID, "gpgme_new failed: %s %s\n", gpgme_strsource( error ), gpgme_strerror( error ) );
		return NULL;
	}

	// get key by fingerprint
	error = gpgme_get_key( ctx, fpr, &key, 1 );
	if( error || key == NULL ) {
		purple_debug_error( PLUGIN_ID, "gpgme_get_key failed: %s %s\n", gpgme_strsource( error ), gpgme_strerror( error ) );
		gpgme_release( ctx );
		return NULL;
	}

	// select signers
	gpgme_signers_clear( ctx );
	error = gpgme_signers_add( ctx, key );
	if( error ) {
		purple_debug_error( PLUGIN_ID, "gpgme_signers_add failed: %s %s\n", gpgme_strsource( error ), gpgme_strerror( error ) );
		gpgme_key_release( key );
		gpgme_release( ctx );
		return NULL;
	}
	// release the key
	gpgme_key_release( key );

	// create data containers
	error = gpgme_data_new_from_mem( &plain, plain_str, strlen( plain_str ), 1 );
	if( error ) {
		purple_debug_error( PLUGIN_ID, "gpgme_data_new_from_mem failed: %s %s\n", gpgme_strsource( error ), gpgme_strerror( error ) );
		gpgme_release( ctx );
		return NULL;
	}
	error = gpgme_data_new( &sig );
	if( error ) {
		purple_debug_error( PLUGIN_ID, "gpgme_data_new failed: %s %s\n", gpgme_strsource( error ), gpgme_strerror( error ) );
		gpgme_data_release( plain );
		gpgme_release( ctx );
		return NULL;
	}

	// sign message, ascii armored
	gpgme_set_armor( ctx, 1 );
	error = gpgme_op_sign( ctx, plain, sig, GPGME_SIG_MODE_DETACH );
	if( error ) {
		purple_debug_error( PLUGIN_ID, "gpgme_op_sign failed: %s %s\n", gpgme_strsource( error ), gpgme_strerror( error ) );
		gpgme_data_release( sig );
		gpgme_data_release( plain );
		gpgme_release( ctx );
		return NULL;
	}

	// release memory for data containers
	gpgme_data_release( plain );
	sig_str = gpgme_data_release_and_get_mem( sig, &len );
	if( sig_str != NULL ) {
		if( len > 0 && ( sig_str_tmp = g_malloc( len + 1 ) ) != NULL ) {
			strncpy( sig_str_tmp, sig_str, len );
			sig_str_tmp[ len ] = 0;
			sig_str_dup = str_pgp_unwrap( sig_str_tmp );
			g_free( sig_str_tmp );
		}
		gpgme_free( sig_str );
	}
	
	// release resources
	gpgme_release( ctx );

	return sig_str_dup;
}

/* ------------------
 * verify a signed string with the key found with fingerprint fpr
 * FREE MEMORY AFTER USAGE OF RETURN VALUE!
 * ------------------ */
static char* verify( const char* sig_str ) {
	if( sig_str == NULL ) {
		purple_debug_error( PLUGIN_ID, "verify: missing sig_str\n" );
		return NULL;
	}

	gpgme_error_t			error;
	gpgme_ctx_t				ctx;
	gpgme_data_t			plain, sig, sig_text;
	gpgme_verify_result_t	result;
	char*					fpr = NULL;
	char*					armored_sig_str = NULL;

	// connect to gpgme
	gpgme_check_version( NULL );
	error = gpgme_new( &ctx );
	if( error ) {
		purple_debug_error( PLUGIN_ID, "gpgme_new failed: %s %s\n", gpgme_strsource( error ), gpgme_strerror( error ) );
		return NULL;
	}

	// armor sig_str
	armored_sig_str = str_pgp_wrap( sig_str, TRUE );
	if( armored_sig_str == NULL ) {
		purple_debug_error( PLUGIN_ID, "str_pgp_wrap failed: could not wrap signature\n" );
		gpgme_release( ctx );
		return NULL;
	}

	// create data containers
	error = gpgme_data_new_from_mem( &sig, armored_sig_str, strlen( armored_sig_str ), 0 );
	if( error ) {
		purple_debug_error( PLUGIN_ID, "gpgme_data_new_from_mem failed: %s %s\n", gpgme_strsource( error ), gpgme_strerror( error ) );
		g_free( armored_sig_str );
		gpgme_release( ctx );
		return NULL;
	}
	error = gpgme_data_new( &plain );
	if( error ) {
		purple_debug_error( PLUGIN_ID, "gpgme_data_new failed: %s %s\n", gpgme_strsource( error ), gpgme_strerror( error ) );
		gpgme_data_release( sig );
		g_free( armored_sig_str );
		gpgme_release( ctx );
		return NULL;
	}

	// try to verify
	error = gpgme_op_verify( ctx, sig, NULL, plain );
	if( error ) {
		purple_debug_error( PLUGIN_ID, "gpgme_op_verify failed: %s %s\n", gpgme_strsource( error ), gpgme_strerror( error ) );
		gpgme_data_release( sig );
		gpgme_data_release( plain );
		g_free( armored_sig_str );
		gpgme_release( ctx );
		return NULL;
	}

	// get result
 	result = gpgme_op_verify_result( ctx );
	if( result != NULL && result->signatures != NULL ) {
		// return the fingerprint of the key that made the signature
		fpr = g_strdup( result->signatures->fpr );
	}

	// release resources
	gpgme_data_release( plain );
	gpgme_data_release( sig );
	g_free( armored_sig_str );
	gpgme_release( ctx );

	return fpr;
}

/* ------------------
 * encrypt a plain string with the key found with fingerprint fpr
 * FREE MEMORY AFTER USAGE OF RETURN VALUE!
 * ------------------ */
static char* encrypt( gpgme_ctx_t* ctx, gpgme_key_t* key_arr, const char* plain_str, const char* fpr ) {
	if( ctx == NULL ) {
		purple_debug_error( PLUGIN_ID, "encrypt: missing ctx\n" );
		return NULL;
	}
	if( key_arr == NULL ) {
		purple_debug_error( PLUGIN_ID, "encrypt: missing key_arr\n" );
		return NULL;
	}
	if( plain_str == NULL ) {
		purple_debug_error( PLUGIN_ID, "encrypt: missing plain_str\n" );
		return NULL;
	}
	if( fpr == NULL ) {
		purple_debug_error( PLUGIN_ID, "encrypt: missing fpr\n" );
		return NULL;
	}

	gpgme_error_t			error;
	gpgme_data_t			plain,	cipher;
	const char*				sender_fpr;
	char*					cipher_str = NULL;
	char*					cipher_str_dup = NULL;
	size_t					len;

	// connect to gpgme, if the context doesn't exist
	if( *ctx == NULL ) {
		gpgme_check_version( NULL );
		error = gpgme_new( ctx );
		if( error ) {
			purple_debug_error( PLUGIN_ID, "gpgme_new failed: %s %s\n", gpgme_strsource( error ), gpgme_strerror( error ) );
			return NULL;
		}
	}

	// get key by fingerprint, if it doesn't exist
	if( key_arr[ 0 ] == NULL ) {
		error = gpgme_get_key( *ctx, fpr, &key_arr[ 0 ], 0 );
		if( error || key_arr[ 0 ] == NULL ) {
			purple_debug_error( PLUGIN_ID, "gpgme_get_key failed: %s %s\n", gpgme_strsource( error ), gpgme_strerror( error ) );
			return NULL;
		}
	}

	// get sender key by fingerprint, if it doesn't exist
	if( key_arr[ 1 ] == NULL ) {
		// check if user selected a main key
		sender_fpr = purple_prefs_get_string( PREF_MY_KEY );
		if( sender_fpr != NULL && strcmp( sender_fpr, "" ) != 0 ) {
			// get own key by fingerprint
			error = gpgme_get_key( *ctx, sender_fpr, &key_arr[ 1 ], 0 );
			if( error || key_arr[ 1 ] == NULL )
				purple_debug_error( PLUGIN_ID, "gpgme_get_key: sender key for fingerprint %s is missing! error: %s %s\n", sender_fpr, gpgme_strsource( error ), gpgme_strerror( error ) );
		} else
			purple_debug_error( PLUGIN_ID, "purple_prefs_get_string: PREF_MY_KEY was empty\n");
	}

	// create data containers
	error = gpgme_data_new_from_mem( &plain, plain_str, strlen( plain_str ), 1 );
	if( error ) {
		purple_debug_error( PLUGIN_ID, "gpgme_data_new_from_mem failed: %s %s\n", gpgme_strsource( error ), gpgme_strerror( error ) );
		return NULL;
	}
	error = gpgme_data_new( &cipher );
	if( error ) {
		purple_debug_error( PLUGIN_ID, "gpgme_data_new failed: %s %s\n", gpgme_strsource( error ), gpgme_strerror( error ) );
		gpgme_data_release( plain );
		return NULL;
	}

	// encrypt, ascii armored
	gpgme_set_armor( *ctx, 1 );
	error = gpgme_op_encrypt( *ctx, key_arr, GPGME_ENCRYPT_ALWAYS_TRUST, plain, cipher );
	if( error ) {
		purple_debug_error( PLUGIN_ID, "gpgme_op_encrypt failed: %s %s\n", gpgme_strsource( error ), gpgme_strerror( error ) );
		gpgme_data_release( cipher );
		gpgme_data_release( plain );
		return NULL;
	}

	// release memory for data containers
	gpgme_data_release( plain );
	cipher_str = gpgme_data_release_and_get_mem( cipher, &len );
	if( cipher_str != NULL ) {
		cipher_str_dup = str_pgp_unwrap( cipher_str );
		if( cipher_str_dup == NULL ) {
			purple_debug_error( PLUGIN_ID, "str_pgp_unwrap failed, the armored message seems to be incorrect: %s\n", cipher_str );
			gpgme_free( cipher_str );
			return NULL;
		}
		gpgme_free( cipher_str );
	}

	return cipher_str_dup;
}

/* ------------------
 * decrypt a plain string with the key found with fingerprint fpr
 * FREE MEMORY AFTER USAGE OF RETURN VALUE
 * ------------------ */
static char* decrypt( char* cipher_str ) {
	if( cipher_str == NULL ) {
		purple_debug_error( PLUGIN_ID, "decrypt: missing cipher_str\n" );
		return NULL;
	}

	gpgme_error_t			error;
	gpgme_ctx_t				ctx;
	gpgme_data_t			plain,	cipher;
	size_t					len = 0;
	char*					plain_str = NULL;
	char*					plain_str_dup = NULL;
	char*					armored_buffer;

	// add header and footer:
	armored_buffer = str_pgp_wrap( cipher_str, FALSE );
	if( armored_buffer == NULL ) {
		purple_debug_error( PLUGIN_ID, "str_pgp_wrap failed: could not wrap message\n" );
		return NULL;
	}

	// connect to gpgme
	gpgme_check_version( NULL );
	error = gpgme_new( &ctx );
	if( error ) {
		purple_debug_error( PLUGIN_ID, "gpgme_new failed: %s %s\n", gpgme_strsource( error ), gpgme_strerror( error ) );
		g_free( armored_buffer );
		return NULL;
	}

	// create data containers
	error = gpgme_data_new_from_mem( &cipher, armored_buffer, strlen( armored_buffer ), 0 );
	if( error ) {
		purple_debug_error( PLUGIN_ID, "gpgme_data_new_from_mem failed: %s %s\n", gpgme_strsource( error ), gpgme_strerror( error ) );
		g_free( armored_buffer );
		gpgme_release( ctx );
		return NULL;
	}
	error = gpgme_data_new( &plain );
	if( error ) {
		purple_debug_error( PLUGIN_ID, "gpgme_data_new failed: %s %s\n", gpgme_strsource( error ), gpgme_strerror( error ) );
		gpgme_data_release( cipher );
		g_free( armored_buffer );
		gpgme_release( ctx );
		return NULL;
	}

	// decrypt
	error = gpgme_op_decrypt( ctx, cipher, plain );
	if( error ) {
		purple_debug_error( PLUGIN_ID, "gpgme_op_decrypt failed: %s %s\n", gpgme_strsource( error ), gpgme_strerror( error ) );
		gpgme_data_release( cipher );
		gpgme_data_release( plain );
		g_free( armored_buffer );
		gpgme_release( ctx );
		return NULL;
	}

	// release memory for data containers
	gpgme_data_release( cipher );
	plain_str = gpgme_data_release_and_get_mem( plain, &len );
	if( plain_str != NULL ) {
		if( len > 0 && ( plain_str_dup = g_malloc( len + 1 ) ) != NULL ) {
			strncpy( plain_str_dup, plain_str, len );
			plain_str_dup[ len ] = 0;
		}
		gpgme_free( plain_str );
	}

	// release resources
	g_free( armored_buffer );
	gpgme_release( ctx );

	return plain_str_dup;
}

/* ------------------
 * initialize gpgme lib on module load
 * ------------------ */
static void init_gpgme () {
	const char*				version;

	/* Initialize the locale environment.  */
	setlocale( LC_ALL, "" );
	version = gpgme_check_version( NULL );
	purple_debug_info( PLUGIN_ID, "Found gpgme version: %s\n", version );

	gpgme_set_locale( NULL, LC_CTYPE, setlocale( LC_CTYPE, NULL ) );
	// For W32 portability.
	#ifdef LC_MESSAGES
	gpgme_set_locale( NULL, LC_MESSAGES, setlocale( LC_MESSAGES, NULL ) );
	#endif
}

/* ------------------
 * called on received message
 * ------------------ */
static gboolean jabber_message_received( PurpleConnection* pc, const char* type, const char* id, const char* from, const char* to, xmlnode* message ) {
	if( pc == NULL ) {
		purple_debug_error( PLUGIN_ID, "jabber_message_received: missing pc\n" );
		return FALSE;
	}
	if( from == NULL ) {
		purple_debug_error( PLUGIN_ID, "jabber_message_received: missing from\n" );
		return FALSE;
	}
	if( message == NULL ) {
		purple_debug_error( PLUGIN_ID, "jabber_message_received: missing message\n" );
		return FALSE;
	}

	const xmlnode*			parent_node = message;
	xmlnode					*x_node = NULL, *body_node = NULL;
	char					*data, *bare_jid_own, *bare_jid, *cipher_str, *plain_str;
	const char*				header = "-----BEGIN PGP PUBLIC KEY BLOCK-----";
	struct list_item*		item = NULL;

	// check if message is a key
	body_node = xmlnode_get_child( parent_node, "body" );
	if( body_node != NULL )	{
		data = xmlnode_get_data( body_node );
		if( data != NULL && strncmp( data, header, strlen( header ) ) == 0 ) {
			// if we received a ascii armored key
			// try to import it
			//purple_conversation_write(conv,"","received key",PURPLE_MESSAGE_SYSTEM | PURPLE_MESSAGE_NO_LOG,time(NULL));
			if( import_key( data ) == TRUE ) {
				xmlnode_clear_data( body_node );
				xmlnode_insert_data( body_node, "key import ok", -1 );
			} else {
				xmlnode_clear_data( body_node );
				xmlnode_insert_data( body_node, "key import failed", -1 );
			}
		}
	}

	// check if the user with the jid=from has signed his presence
	bare_jid = get_bare_jid( from );
	if( bare_jid != NULL ) {
		bare_jid_own = get_bare_jid( purple_connection_get_account( pc )->username );
		if( bare_jid_own != NULL ) {
			// use from or to depending on whether it's a carbonated sent message
			if( to != NULL && strcmp( bare_jid, bare_jid_own ) == 0 ) {
				g_free( bare_jid );
				bare_jid = get_bare_jid( to );
			}
			// get stored info about user
			item = g_hash_table_lookup( list_fingerprints, bare_jid );
			g_free( bare_jid_own );
		}
		if( bare_jid != NULL )
			g_free( bare_jid );
	}

	// We don't set item->mode_sec = FALSE here because of any received message that is not encrypted.
	// forwarded non-encrypted messages (receipts etc.) will otherwise disable encryption
	
	// check if message has special "x" child node => encrypted message
	x_node = xmlnode_get_child_with_namespace( parent_node, "x", NS_ENC );
	if( x_node != NULL ) {
		purple_debug_info( PLUGIN_ID, "user %s sent us an encrypted message\n", from );

		// get data of "x" node
		cipher_str = xmlnode_get_data( x_node );
		if( cipher_str != NULL ) {
			// try to decrypt
			plain_str = decrypt( cipher_str );
			if( plain_str != NULL ) {
				//purple_debug_info( PLUGIN_ID, "decrypted message: %s\n",plain_str);
				// find body node
				body_node = xmlnode_get_child( parent_node, "body" );
				if( body_node != NULL ) {
					// clear body node data if it is found
					xmlnode_clear_data( body_node );
				} else {
					// add body node if it is not found
					body_node = xmlnode_new_child( message, "body" );
				}
				// set "body" content node to decrypted string
				//xmlnode_insert_data( body_node, "Encrypted message: ", -1 );
				xmlnode_insert_data( body_node, plain_str, -1 );

				// only set to encrypted mode, if we know other users key fingerprint
				if( item != NULL ) {
					// all went well, we received an encrypted message
					item->mode_sec = TRUE;
				}

				g_free( plain_str );
			} else
				purple_debug_error( PLUGIN_ID, "could not decrypt message!\n" );
		} else
			purple_debug_error( PLUGIN_ID, "xml token had no data!\n" );
	}

	// We don't want the plugin to stop processing
	return FALSE;
}

/* ------------------
 * called on received presence
 * ------------------ */
static gboolean jabber_presence_received( PurpleConnection* pc, const char* type, const char* from, xmlnode* presence ) {
	if( from == NULL ) {
		purple_debug_error( PLUGIN_ID, "jabber_presence_received: missing from\n" );
		return FALSE;
	}
	if( presence == NULL ) {
		purple_debug_error( PLUGIN_ID, "jabber_presence_received: missing presence\n" );
		return FALSE;
	}

	const xmlnode*			parent_node = presence;
	xmlnode*				x_node = NULL;
	char					*x_node_data, *fpr, *bare_jid;
	struct list_item*		item;

	// check if presence has special "x" childnode
	x_node = xmlnode_get_child_with_namespace( parent_node, "x" ,NS_SIGNED );
	if( x_node != NULL ) {
		// user supports openpgp encryption
		purple_debug_info( PLUGIN_ID, "user %s supports openpgp encryption!\n", from );

		x_node_data = xmlnode_get_data( x_node );
		if( x_node_data != NULL ) {
			// try to verify
			fpr = verify( x_node_data );
			if( fpr != NULL ) {
				bare_jid = get_bare_jid( from );
				if( bare_jid == NULL ) {
					purple_debug_info( PLUGIN_ID, "jabber_presence_received: get_bare_jid failed for %s\n", from );
					g_free( fpr );
					return FALSE;
				}
				purple_debug_info( PLUGIN_ID, "user %s has fingerprint %s\n", bare_jid, fpr );

				// check if the fpr is already in the list
				item = g_hash_table_lookup( list_fingerprints, bare_jid );
				// clear the entry if the fpr has changed
				if( item != NULL && strcmp( item->fpr, fpr ) != 0 ) {
					g_hash_table_remove( list_fingerprints, bare_jid );
					item = NULL;
				}
				// add key to list if it doesn't exist
				if( item == NULL ) {
					item = g_malloc( sizeof( struct list_item ) );
					if( item == NULL ) {
						purple_debug_info( PLUGIN_ID, "jabber_presence_received: out of memory\n" );
						g_free( fpr );
						g_free( bare_jid );
						return FALSE;
					}
					memset( item, 0, sizeof( struct list_item ) );
					item->fpr = fpr;
					g_hash_table_insert( list_fingerprints, bare_jid, item );
				}
			} else
				purple_debug_error( PLUGIN_ID, "could not verify presence of user %s\n", from );
		} else
			purple_debug_info( PLUGIN_ID, "user %s sent empty signed presence\n", from );
	}

	// We don't want the plugin to stop processing
	return FALSE;
}

/* ------------------
 * called on every sent packet
 * ------------------ */
void jabber_send_signal_cb( PurpleConnection* pc, xmlnode** packet, gpointer unused ) {
	if( packet == NULL ) {
		purple_debug_error( PLUGIN_ID, "jabber_send_signal_cb: missing packet\n" );
		return;
	}

	const char*				status_str = NULL;
	xmlnode					*status_node, *x_node, *body_node;
	const char				*fpr, *to;
	char					*sig_str, *message, *enc_str, *bare_jid;
	struct list_item*		item;

	g_return_if_fail( PURPLE_CONNECTION_IS_VALID( pc ) );

	// if we are sending a presence stanza, add new child node
	//  so others know we support openpgp
	if( g_str_equal( (*packet)->name, "presence" ) ) {
		// check if user selected a main key
		fpr = purple_prefs_get_string( PREF_MY_KEY );
		if( fpr != NULL && strcmp( fpr, "" ) != 0) {
			// user did select a key
			// get status message from packet
			status_node = xmlnode_get_child( *packet, "status" );
			if( status_node != NULL ) {
				status_str = xmlnode_get_data( status_node );
			}

			// sign status message
			if( status_str == NULL )
				status_str = "";
			purple_debug_info( PLUGIN_ID, "signing status '%s' with key %s\n", status_str, fpr );

			sig_str = sign( status_str, fpr );
			if( sig_str == NULL ) {
				purple_debug_error( PLUGIN_ID, "sign failed\n" );
				return;
			}

			// create special "x" childnode
			purple_debug_info( PLUGIN_ID, "sending presence with signature\n" );
			x_node = xmlnode_new_child( *packet, "x" );
			xmlnode_set_namespace( x_node, NS_SIGNED );
			xmlnode_insert_data( x_node, sig_str, -1 );
			g_free( sig_str );
		} else
			purple_debug_info( PLUGIN_ID, "no key selecteded!\n" );
	} else if( g_str_equal( (*packet)->name, "message" ) ) {
		to = xmlnode_get_attrib( *packet, "to" );
		body_node = xmlnode_get_child( *packet, "body" );
		if( body_node != NULL && to != NULL ) {
			// get message
			message = g_strdup( xmlnode_get_data( body_node ) );
			if( message == NULL ) {
				purple_debug_info( PLUGIN_ID, "jabber_send_signal_cb: g_strdup failed\n" );
				return;
			}
			enc_str = NULL;
			bare_jid = get_bare_jid( to );
			if( bare_jid == NULL ) {
				purple_debug_info( PLUGIN_ID, "jabber_send_signal_cb: get_bare_jid failed for %s\n", to );
				g_free( message );
				return;
			}

			// get encryption key
			item = g_hash_table_lookup( list_fingerprints, bare_jid );
			if( item == NULL ) {
				purple_debug_info( PLUGIN_ID, "there is no key for encrypting message to %s\n", bare_jid );
				g_free( message );
				g_free( bare_jid );
				return;
			}
			// do not encrypt if mode_sec is disabled
			if( item->mode_sec == FALSE ) {
				g_free( message );
				g_free( bare_jid );
				return;
			}
			purple_debug_info( PLUGIN_ID, "found key for encryption to user %s: %s\n", bare_jid, item->fpr );
			g_free( bare_jid );

			// encrypt message
			enc_str = encrypt( &item->ctx, item->key_arr, message, item->fpr );
			g_free( message );
			if( enc_str != NULL ) {
				// remove message from body
				xmlnode_clear_data( body_node );
				xmlnode_insert_data( body_node, "[ERROR: This message is encrypted, and you are unable to decrypt it.]" , -1 );

				// add special "x" childnode for encrypted text
				purple_debug_info( PLUGIN_ID, "sending encrypted message\n" );
				x_node = xmlnode_new_child( *packet, "x" );
				xmlnode_set_namespace( x_node, NS_ENC );
				xmlnode_insert_data( x_node, enc_str, -1 );
				g_free( enc_str );
			} else
				purple_debug_error( PLUGIN_ID, "could not encrypt message\n" );
		} else {
			// ignore this type of messages
			//purple_debug_warning( PLUGIN_ID, "empty message or empty 'to'\n");
		}
	}
}

/* ------------------
 * called on new conversations
 * ------------------ */
void conversation_created_cb( PurpleConversation* conv, char* data ) {
	if( conv == NULL ) {
		purple_debug_error( PLUGIN_ID, "conversation_created_cb: missing conv\n" );
		return;
	}
	if( purple_conversation_get_type( conv ) != PURPLE_CONV_TYPE_IM )
		return;

	char					sys_msg_buffer[1000];
	char					*bare_jid, *userid = NULL;
	struct list_item*		item;

	// check if the user with the jid=conv->name has signed his presence
	bare_jid = get_bare_jid( conv->name );
	if( bare_jid == NULL ) {
		purple_debug_info( PLUGIN_ID, "conversation_created_cb: get_bare_jid failed for %s\n", conv->name );
		return;
	}
	purple_debug_info( PLUGIN_ID, "conversation name: %s bare jid: %s\n", conv->name, bare_jid );

	// get stored info about user
	item = g_hash_table_lookup( list_fingerprints, bare_jid );
	if( item != NULL ) {
		// check if we have key locally
		if( is_key_available( &item->ctx, item->key_arr, item->fpr, FALSE, FALSE, &userid ) == FALSE ) {
			// local key is missing
			sprintf( sys_msg_buffer, "User has key with Fingerprint %s, but we do not have it locally. Try Options -> \"Try to retrieve key of '%s' from server\"", item->fpr, bare_jid );
		} else {
			// key is already available locally -> enable mode_enc
			sprintf( sys_msg_buffer, "Encryption enabled with %s (%s)", userid, item->fpr );
			item->mode_sec = TRUE;
		}
		if( userid != NULL )
			g_free( userid );
		userid = NULL;
	}else
		sprintf( sys_msg_buffer, "Encryption disabled, the remote client doesn't support it." );

	// display message about received message
	purple_conversation_write( conv, "", sys_msg_buffer, PURPLE_MESSAGE_SYSTEM | PURPLE_MESSAGE_NO_LOG, time( NULL ) );

	// release resources
	g_free( bare_jid );
}

/* ------------------
 * called before display of received messages
 * ------------------ */
static gboolean receiving_im_msg_cb( PurpleAccount* account, char** sender, char** buffer, PurpleConversation* conv, PurpleMessageFlags* flags, void* data ) {
	if( sender == NULL || *sender == NULL ) {
		purple_debug_error( PLUGIN_ID, "receiving_im_msg_cb: missing sender\n" );
		return FALSE;
	}

	char					sys_msg_buffer[1000];
	char*					bare_jid;
	struct list_item*		item;

	// check if the user with the jid=conv->name has signed his presence
	bare_jid = get_bare_jid( *sender );
	if( bare_jid == NULL ) {
		purple_debug_info( PLUGIN_ID, "receiving_im_msg_cb: get_bare_jid failed for %s\n", *sender );
		return FALSE;
	}

	// set default message
	sprintf( sys_msg_buffer, "Encryption disabled" );

	// get encryption key
	item = g_hash_table_lookup( list_fingerprints, bare_jid );
	if( item != NULL ) {
		if( item->mode_sec == TRUE )
			sprintf( sys_msg_buffer, "Encryption enabled" );

		// display a basic message, only if mode changed
		if( item->mode_sec != item->mode_sec_old )
			purple_conversation_write( conv, "", sys_msg_buffer, PURPLE_MESSAGE_SYSTEM | PURPLE_MESSAGE_NO_LOG, time( NULL ) );
		item->mode_sec_old = item->mode_sec;
	}

	// release resources
	g_free( bare_jid );

	return FALSE;
}

/* ------------------
 * conversation menu action, that toggles mode_sec
 * ------------------ */
static void menu_action_toggle_cb( PurpleConversation* conv, void* data ) {
	if( conv == NULL ) {
		purple_debug_error( PLUGIN_ID, "menu_action_toggle_cb: missing conv\n" );
		return;
	}

	char*					bare_jid;
	struct list_item*		item;

	// check if the user with the jid=conv->name has signed his presence
	bare_jid = get_bare_jid( conv->name );
	if( bare_jid == NULL ) {
		purple_debug_info( PLUGIN_ID, "menu_action_toggle_cb: get_bare_jid failed for %s\n", conv->name );
		return;
	}

	// get stored info about user
	item = g_hash_table_lookup( list_fingerprints, bare_jid );
	if( item != NULL ) {
		item->mode_sec = !( item->mode_sec );
		item->mode_sec_old = item->mode_sec;

		// tell user, that we toggled mode
		purple_conversation_write( conv, "", item->mode_sec ? "Encryption enabled" : "Encryption disabled", PURPLE_MESSAGE_SYSTEM | PURPLE_MESSAGE_NO_LOG, time( NULL ) );
	}

	// release resources
	g_free( bare_jid );
}

/* ------------------
 * send public key to other person in conversation
 * ------------------ */
static void menu_action_sendkey_cb( PurpleConversation* conv, void* data ) {
	const char*				fpr;
	char*					key = NULL;
	PurpleConvIm*			im_data;

	// check if user selected a main key
	fpr = purple_prefs_get_string( PREF_MY_KEY );
	if( fpr != NULL && strcmp( fpr, "" ) != 0 ) {
		// get key
		key = get_key_armored( fpr );
		if( key != NULL ) {
			// send key
			im_data = purple_conversation_get_im_data( conv );
			if( im_data != NULL ) {
				purple_conv_im_send_with_flags( im_data, key, PURPLE_MESSAGE_SYSTEM | PURPLE_MESSAGE_INVISIBLE | PURPLE_MESSAGE_RAW );
				purple_conversation_write( conv, "", "Public key sent!", PURPLE_MESSAGE_SYSTEM | PURPLE_MESSAGE_NO_LOG, time( NULL ) );
			}
			g_free( key );
		}
	} else
		purple_conversation_write( conv, "", "You haven't selected a personal key yet.", PURPLE_MESSAGE_SYSTEM | PURPLE_MESSAGE_NO_LOG, time( NULL ) );
}

/* ------------------
 * try to retrieve key from server
 * ------------------ */
static void menu_action_retrievekey_cb( PurpleConversation* conv, void* data ) {
	if( conv == NULL ) {
		purple_debug_error( PLUGIN_ID, "menu_action_retrievekey_cb: missing conv\n" );
		return;
	}

	char					sys_msg_buffer[ 1000 ];
	char					*bare_jid, *userid = NULL;
	struct list_item*		item;

	// check if the user with the jid=conv->name has signed his presence
	bare_jid = get_bare_jid( conv->name );
	if( bare_jid == NULL ) {
		purple_debug_info( PLUGIN_ID, "menu_action_retrievekey_cb: get_bare_jid failed for %s\n", conv->name );
		return;
	}

	// get stored info about user
	item = g_hash_table_lookup( list_fingerprints, bare_jid );
	if( item != NULL ) {
		if( is_key_available( &item->ctx, item->key_arr, item->fpr, FALSE, TRUE, &userid ) == FALSE ) {
			sprintf( sys_msg_buffer, "Did not find key with ID '%s' on keyservers.", item->fpr );
			purple_conversation_write( conv, "", sys_msg_buffer, PURPLE_MESSAGE_SYSTEM | PURPLE_MESSAGE_NO_LOG, time( NULL ) );
		} else {
			// found key -> enable mode_enc
			sprintf( sys_msg_buffer, "Found key with ID '%s'/'%s' for '%s' on keyservers.", item->fpr, userid, bare_jid );
			purple_conversation_write( conv, "", sys_msg_buffer, PURPLE_MESSAGE_SYSTEM | PURPLE_MESSAGE_NO_LOG, time( NULL ) );
			purple_conversation_write( conv, "", "Encryption enabled", PURPLE_MESSAGE_SYSTEM | PURPLE_MESSAGE_NO_LOG, time( NULL ) );
			item->mode_sec = TRUE;
		}
		if( userid != NULL )
			g_free( userid );
	}

	// release resources
	g_free( bare_jid );
}

/* ------------------
 * conversation extended menu
 * ------------------ */
void conversation_extended_menu_cb( PurpleConversation* conv, GList** list ) {
	if( conv == NULL ) {
		purple_debug_error( PLUGIN_ID, "conversation_extended_menu_cb: missing conv\n" );
		return;
	}
	if( list == NULL ) {
		purple_debug_error( PLUGIN_ID, "conversation_extended_menu_cb: missing list\n" );
		return;
	}

	char					buffer[ 1000 ];
	PurpleMenuAction*		action = NULL;
	char					*bare_jid;
	struct list_item*		item;

	// check if the user with the jid=conv->name has signed his presence
	bare_jid = get_bare_jid( conv->name );
	if( bare_jid == NULL ) {
		purple_debug_info( PLUGIN_ID, "conversation_extended_menu_cb: get_bare_jid failed for %s\n", conv->name );
		return;
	}

	// get stored info about user
	item = g_hash_table_lookup( list_fingerprints, bare_jid );
	if( item != NULL ) {
		// on display encryption menu item, if user sent signed presence
		action = purple_menu_action_new( "Toggle OPENPGP encryption", PURPLE_CALLBACK( menu_action_toggle_cb ), NULL, NULL );
		*list = g_list_append( *list, action );

		sprintf( buffer, "Send own public key to '%s'", bare_jid );
		action = purple_menu_action_new( buffer, PURPLE_CALLBACK( menu_action_sendkey_cb ), NULL, NULL );
		*list = g_list_append( *list, action );
		
		sprintf( buffer, "Try to retrieve key of '%s' from server", bare_jid );
		action = purple_menu_action_new( buffer, PURPLE_CALLBACK( menu_action_retrievekey_cb ), NULL, NULL );
		*list = g_list_append( *list, action );
	}

	// release resources
	g_free( bare_jid );
}

/* ------------------
 * called before message is sent
 * ------------------ */
void sending_im_msg_cb( PurpleAccount* account, const char* receiver, char** message) {
	PurpleConversation*		gconv = NULL;
	char					*bare_jid;
	struct list_item*		item;

	// search for conversation
	gconv = purple_find_conversation_with_account( PURPLE_CONV_TYPE_IM, receiver, account );
	if( gconv ) {
		// check if the user with the jid=conv->name has signed his presence
		bare_jid = get_bare_jid( gconv->name );
		if( bare_jid == NULL ) {
			purple_debug_info( PLUGIN_ID, "sending_im_msg_cb: get_bare_jid failed for %s\n", gconv->name );
			return;
		}

		// get stored info about user
		item = g_hash_table_lookup( list_fingerprints, bare_jid );
		if( item != NULL ) {
			// if we are in private mode
			if( item->mode_sec == TRUE ) {
				// try to get key
				if( is_key_available( &item->ctx, item->key_arr, item->fpr, FALSE, FALSE, NULL ) == FALSE ) {
					// we do not have key of receiver
					// -> cancel message sending
					if( message != NULL && *message != NULL ) {
						g_free( *message );
						*message = NULL;
					}

					// tell user of this
					purple_conversation_write( gconv, "", "The key of the receiver is not available, please ask the receiver for the key before trying to encrypt messages.", PURPLE_MESSAGE_SYSTEM | PURPLE_MESSAGE_NO_LOG, time( NULL ) );
				}
			}
		}

		// release resources
		g_free( bare_jid );
	}
}

/* ------------------
 * called on module load
 * ------------------ */
static gboolean plugin_load( PurplePlugin* plugin ) {
	void					*jabber_handle, *conv_handle;

	// check if hashtable already created
	if( list_fingerprints == NULL )
		list_fingerprints = g_hash_table_new_full( g_str_hash, g_str_equal, g_free, list_item_destroy );

	// register presence receiver handler
	jabber_handle   = purple_plugins_find_with_id( "prpl-jabber" );
	conv_handle     = purple_conversations_get_handle();

	if( conv_handle != NULL ) {
		purple_signal_connect( conv_handle, "conversation-created",			plugin, PURPLE_CALLBACK( conversation_created_cb ),			NULL );
		purple_signal_connect( conv_handle, "receiving-im-msg",				plugin, PURPLE_CALLBACK( receiving_im_msg_cb ),				NULL );
		purple_signal_connect( conv_handle, "conversation-extended-menu",	plugin, PURPLE_CALLBACK( conversation_extended_menu_cb ),	NULL );
		purple_signal_connect( conv_handle, "sending-im-msg",				plugin, PURPLE_CALLBACK( sending_im_msg_cb ),				NULL) ;
	} else
		return FALSE;

	if( jabber_handle ) {
		purple_signal_connect( jabber_handle, "jabber-receiving-message",	plugin, PURPLE_CALLBACK( jabber_message_received ),			NULL );
		purple_signal_connect( jabber_handle, "jabber-receiving-presence",	plugin, PURPLE_CALLBACK( jabber_presence_received ),		NULL );
		purple_signal_connect( jabber_handle, "jabber-sending-xmlnode",		plugin, PURPLE_CALLBACK( jabber_send_signal_cb ),			NULL );
	} else
		return FALSE;

	/*
	Initialize everything needed; get the passphrase for encrypting and decrypting messages.
	Attach to all windows the chat windows.
	*/
/*	attach_to_all_windows();
	purple_signal_connect( pidgin_conversations_get_handle(), "conversation-displayed",		plugin, PURPLE_CALLBACK( conv_created ), NULL );
	purple_signal_connect( purple_conversations_get_handle(), "conversation-extended-menu",	plugin, PURPLE_CALLBACK( conv_menu_cb ), NULL );*/

	// initialize gpgme lib on module load
	init_gpgme();

	return TRUE;
}

/* ------------------
 * called on module unload
 * ------------------ */
static gboolean plugin_unload( PurplePlugin* plugin ) {
	//detach_from_all_windows();

	// free resources
	if( list_fingerprints == NULL )
		g_hash_table_destroy( list_fingerprints );

	return TRUE;
}

/* ------------------
 * preferences dialog function
 * ------------------ */
static PurplePluginPrefFrame* get_plugin_pref_frame( PurplePlugin* plugin ) {
	PurplePluginPrefFrame	*frame;
	PurplePluginPref		*ppref;
	gpgme_error_t			error;
	gpgme_ctx_t				ctx;
	gpgme_key_t				key;

	// create preferences frame
	frame = purple_plugin_pref_frame_new();
	
	// connect to gpgme
	gpgme_check_version( NULL );
	error = gpgme_new( &ctx );
	if( error ) {
		purple_debug_error( PLUGIN_ID, "gpgme_new failed: %s %s\n", gpgme_strsource( error ), gpgme_strerror( error ) );
		return NULL;
	}

	// create key chooser preference
	ppref = purple_plugin_pref_new_with_name_and_label( PREF_MY_KEY, "My key" );
	purple_plugin_pref_set_type( ppref, PURPLE_PLUGIN_PREF_CHOICE );
	purple_plugin_pref_add_choice( ppref, "None", "" );

	// list keys (secret keys)
	error = gpgme_op_keylist_start( ctx, NULL, 1 );
	if( error == GPG_ERR_NO_ERROR ) {
		while( !error ) {
			error = gpgme_op_keylist_next( ctx, &key );
			if( error )
				break;
			// add key to preference chooser
			//TODO: find something better for g_strdup, or some possibility to free memory after preferences dialog closed
			purple_plugin_pref_add_choice( ppref, g_strdup( key->uids->uid ), g_strdup( key->subkeys->fpr ) );
			purple_debug_info( PLUGIN_ID, "Found secret key for: %s has fpr %s\n", key->uids->uid, key->subkeys->fpr );
			gpgme_key_release( key );
		}
	} else
		purple_debug_error( PLUGIN_ID, "gpgme_op_keylist_start failed: %s %s\n", gpgme_strsource( error ), gpgme_strerror( error ) );

	// release resources
	gpgme_release( ctx );

	// add the frame
	purple_plugin_pref_frame_add( frame, ppref );

	return frame;
}

/* ------------------
 * The plugin ui info struct for preferences dialog
 * ------------------ */
static PurplePluginUiInfo prefs_info = {
	get_plugin_pref_frame,
	0,   /* page_num (Reserved) */
	NULL, /* frame (Reserved) */
	/* Padding */
	NULL,
	NULL,
	NULL,
	NULL
};

/* ------------------
 * The plugin info struct
 * ------------------ */
static PurplePluginInfo info = {
    PURPLE_PLUGIN_MAGIC,
    PURPLE_MAJOR_VERSION,
    PURPLE_MINOR_VERSION,
    PURPLE_PLUGIN_STANDARD,
    NULL,
    0,
    NULL,
    PURPLE_PRIORITY_DEFAULT,

    PLUGIN_ID,
    "GPG/OPENPGP (XEP-0027)",
    "0.9",

    "GPG Plugin for Pidgin",          
    "Simple GPG Plugin for Pidgin.",          
    "Alexander Murauer <segler_alex@web.de>",
    "https://github.com/segler-alex/Pidgin-GPG",     
    
    plugin_load,                   
    NULL,                          
    NULL,                          
                                   
    NULL,                          
    NULL,                          
    &prefs_info,                        
    NULL,                   
    NULL,                          
    NULL,                          
    NULL,                          
    NULL                           
};                               

/* ------------------
 * plugin init
 * ------------------ */
static void init_plugin( PurplePlugin *plugin ) {
	// create entries in prefs if they are not there
	purple_prefs_add_none( PREF_ROOT );
	purple_prefs_add_string( PREF_MY_KEY, "" );
}

PURPLE_INIT_PLUGIN( pidgin-gpg, init_plugin, info )
