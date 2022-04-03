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

#include				"../config.h"

#include				<locale.h>
#include				<string.h>
#include				<stdbool.h>

#include				"notify.h"
#include				"plugin.h"
#include				"version.h"

#include				<pluginpref.h>
#include				<prefs.h>
#include				<debug.h>

#include				<gtkconv.h>
#include				<gtk/gtk.h>
#include				<gpgme.h>

static GHashTable*		list_fingerprints = NULL;

static const char*		GPG_CHECK_BTN_ENCR_ENABLED	= "gpg-check-bnt-ecnr-enabled";

static const char*		PREF_ROOT		= "/plugins/core/core-segler-pidgin-gpg";
static const char*		PREF_MY_KEY		= "/plugins/core/core-segler-pidgin-gpg/my_key_fpr";
static const char*		PREF_PUB_KEY_FPR= "GPG/pub_key_fpr";

static const char*		NS_SIGNED		= "jabber:x:signed";
static const char*		NS_ENC			= "jabber:x:encrypted";

static const char		PGP_MSG_HEADER[]	= "-----BEGIN PGP MESSAGE-----";
static const char		PGP_MSG_FOOTER[]	= "-----END PGP MESSAGE-----";
static const char		PGP_SIG_HEADER[]	= "-----BEGIN PGP SIGNATURE-----";
static const char		PGP_SIG_FOOTER[]	= "-----END PGP SIGNATURE-----";

/* ------------------
 * The plugin ui info struct for preferences dialog
 * ------------------ */
static PurplePluginPrefFrame* get_plugin_pref_frame( PurplePlugin* plugin );
static PurplePluginUiInfo prefs_info = {
	.get_plugin_pref_frame = get_plugin_pref_frame
};

/* ------------------
 * The plugin info struct
 * ------------------ */
static gboolean plugin_load( PurplePlugin* plugin );
static PurplePluginInfo info = {
	.magic = PURPLE_PLUGIN_MAGIC,
	.major_version = PURPLE_MAJOR_VERSION,
	.minor_version = PURPLE_MINOR_VERSION,
	.type = PURPLE_PLUGIN_STANDARD,
	.priority = PURPLE_PRIORITY_DEFAULT,

	.id = "core-segler-pidgin-gpg",
	.name = "GPG/OPENPGP (XEP-0027)",
	.version = "0.9",

	.summary = "GPG Plugin for Pidgin",
	.description = "Simple GPG Plugin for Pidgin.",
	.author = "Andrey Sokolov <keremet@solaris.kirov.ru>",
	.homepage = "https://github.com/keremet/pidgin-gpg",

	.load = plugin_load,
	.unload = NULL,
	.destroy = NULL,

	.prefs_info = &prefs_info
};

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
};

static inline bool is_empty_str( const char* s ) {
	return (s[0] == '\0');
}

/* ------------------
 * Use g_strdup for arguments
 * ------------------ */
static void list_fingerprints_add( char* bare_jid, char* pub_key_fpr ) {
	if( NULL == list_fingerprints || NULL == bare_jid || NULL == pub_key_fpr )
		return;

	struct list_item* item = g_malloc0( sizeof( struct list_item ) );
	item->fpr = pub_key_fpr;
	g_hash_table_insert( list_fingerprints, bare_jid, item );
}
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
		purple_debug_error( info.id, "str_pgp_wrap: missing unwrappedBuffer\n" );
		return NULL;
	}

	char*					buffer = NULL;

	if( asSignature ) {
		if( ( buffer = g_malloc( (sizeof( PGP_SIG_HEADER ) - 1) + strlen( unwrappedBuffer ) + (sizeof( PGP_SIG_FOOTER ) - 1) + 4 ) ) != NULL ) {
			strcpy( buffer, PGP_SIG_HEADER );
			strcat( buffer, "\n\n" );
			strcat( buffer, unwrappedBuffer );
			strcat( buffer, "\n" );
			strcat( buffer, PGP_SIG_FOOTER );
		}
	} else {
		if( ( buffer = g_malloc( (sizeof( PGP_MSG_HEADER ) - 1) + strlen( unwrappedBuffer ) + (sizeof( PGP_MSG_FOOTER ) - 1) + 4 ) ) != NULL ) {
			strcpy( buffer, PGP_MSG_HEADER );
			strcat( buffer, "\n\n" );
			strcat( buffer, unwrappedBuffer );
			strcat( buffer, "\n" );
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
		purple_debug_error( info.id, "str_pgp_unwrap: missing wrappedBuffer\n" );
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
		purple_debug_error( info.id, "get_bare_jid: missing jid\n" );
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
		purple_debug_error( info.id, "is_key_available: missing ctx\n" );
		return FALSE;
	}
	if( key_arr == NULL ) {
		purple_debug_error( info.id, "is_key_available: missing key_arr\n" );
		return FALSE;
	}
	if( fpr == NULL ) {
		purple_debug_error( info.id, "is_key_available: missing fpr\n" );
		return FALSE;
	}

	gpgme_error_t			error;
	gpgme_keylist_mode_t	current_keylist_mode;

	// connect to gpgme if no context is given to reuse
	if( *ctx == NULL ) {
		gpgme_check_version( NULL );
		error = gpgme_new( ctx );
		if( error ){
			purple_debug_error( info.id, "gpgme_new failed: %s %s\n", gpgme_strsource( error ), gpgme_strerror( error ) );
			return FALSE;
		}
	}

	// if there is no key yet
	if( key_arr[ 0 ] == NULL ) {
		// set to server search mode if servermode == TRUE
		if( servermode == TRUE ) {
			purple_debug_info( info.id, "set keylist mode to server\n" );
			current_keylist_mode = gpgme_get_keylist_mode( *ctx );
			gpgme_set_keylist_mode( *ctx, ( current_keylist_mode | GPGME_KEYLIST_MODE_EXTERN ) & ( ~GPGME_KEYLIST_MODE_LOCAL ) );
		}

		// get key by fingerprint
		error = gpgme_get_key( *ctx, fpr, &key_arr[ 0 ], secret );
		if( error || key_arr[ 0 ] == NULL ) {
			purple_debug_error( info.id, "gpgme_get_key failed: %s %s\n", gpgme_strsource( error ), gpgme_strerror( error ) );
			return FALSE;
		}

		// in server mode
		if( servermode == TRUE ) {
			// unset server search mode
			purple_debug_info( info.id, "set keylist mode to server\n" );
			current_keylist_mode = gpgme_get_keylist_mode( *ctx );
			gpgme_set_keylist_mode( *ctx, ( current_keylist_mode | GPGME_KEYLIST_MODE_LOCAL ) & ( ~GPGME_KEYLIST_MODE_EXTERN ) );

			// import the key
			error = gpgme_op_import_keys( *ctx, key_arr );
			if( error ) {
				purple_debug_error( info.id, "gpgme_op_import_keys failed: %s %s\n", gpgme_strsource( error ), gpgme_strerror( error ) );
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
		purple_debug_error( info.id, "get_key_armored: missing fpr\n" );
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
		purple_debug_error( info.id, "gpgme_new failed: %s %s\n", gpgme_strsource( error ), gpgme_strerror( error ) );
		return NULL;
	}

	// get key by fingerprint
	error = gpgme_get_key( ctx, fpr, &key_arr[ 0 ], 0 );
	if( error || key_arr[ 0 ] == NULL ) {
		purple_debug_error( info.id, "gpgme_get_key failed: %s %s\n", gpgme_strsource( error ), gpgme_strerror( error ) );
		gpgme_release( ctx );
		return NULL;
	}

	// create data containers
	error = gpgme_data_new( &key_data );
	if( error ) {
		purple_debug_error( info.id, "gpgme_data_new failed: %s %s\n", gpgme_strsource( error ), gpgme_strerror( error ) );
		gpgme_key_release( key_arr[ 0 ] );
		gpgme_release( ctx );
		return NULL;
	}

	// export key
	gpgme_set_armor( ctx, 1 );
	error = gpgme_op_export_keys( ctx, key_arr, 0, key_data );
	if( error ) {
		purple_debug_error( info.id, "gpgme_op_export_keys failed: %s %s\n", gpgme_strsource( error ), gpgme_strerror( error ) );
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
int import_key( const char* armored_key ) {
	if( armored_key == NULL ) {
		purple_debug_error( info.id, "import_key: missing armored_key\n" );
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
		purple_debug_error( info.id, "gpgme_new failed: %s %s\n", gpgme_strsource( error ), gpgme_strerror( error ) );
		return FALSE;
	}

	purple_debug_info( info.id, "try to import key: %s\n", armored_key );
	// create data containers
	error = gpgme_data_new_from_mem( &keydata, armored_key, strlen( armored_key ), 1 );
	if( error ) {
		purple_debug_error( info.id, "gpgme_data_new_from_mem failed: %s %s\n", gpgme_strsource( error ), gpgme_strerror( error ) );
		gpgme_release( ctx );
		return FALSE;
	}

	// import key, ascii armored
	gpgme_set_armor( ctx, 1 );
	error =  gpgme_op_import( ctx, keydata );
	if( error ) {
		purple_debug_error( info.id, "gpgme_op_import: %s %s\n", gpgme_strsource( error ), gpgme_strerror( error ) );
		gpgme_data_release( keydata );
		gpgme_release( ctx );
		return FALSE;
	}

	result = gpgme_op_import_result( ctx );
	purple_debug_info( info.id, "considered keys: %d; imported keys: %d; not imported keys: %d\n", result->considered, result->imported, result->not_imported );

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
		purple_debug_error( info.id, "sign: missing plain_str\n" );
		return NULL;
	}
	if( fpr == NULL ) {
		purple_debug_error( info.id, "sign: missing fpr\n" );
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
		purple_debug_error( info.id, "gpgme_new failed: %s %s\n", gpgme_strsource( error ), gpgme_strerror( error ) );
		return NULL;
	}

	// get key by fingerprint
	error = gpgme_get_key( ctx, fpr, &key, 1 );
	if( error || key == NULL ) {
		purple_debug_error( info.id, "gpgme_get_key failed: %s %s\n", gpgme_strsource( error ), gpgme_strerror( error ) );
		gpgme_release( ctx );
		return NULL;
	}

	// select signers
	gpgme_signers_clear( ctx );
	error = gpgme_signers_add( ctx, key );
	if( error ) {
		purple_debug_error( info.id, "gpgme_signers_add failed: %s %s\n", gpgme_strsource( error ), gpgme_strerror( error ) );
		gpgme_key_release( key );
		gpgme_release( ctx );
		return NULL;
	}
	// release the key
	gpgme_key_release( key );

	// create data containers
	error = gpgme_data_new_from_mem( &plain, plain_str, strlen( plain_str ), 1 );
	if( error ) {
		purple_debug_error( info.id, "gpgme_data_new_from_mem failed: %s %s\n", gpgme_strsource( error ), gpgme_strerror( error ) );
		gpgme_release( ctx );
		return NULL;
	}
	error = gpgme_data_new( &sig );
	if( error ) {
		purple_debug_error( info.id, "gpgme_data_new failed: %s %s\n", gpgme_strsource( error ), gpgme_strerror( error ) );
		gpgme_data_release( plain );
		gpgme_release( ctx );
		return NULL;
	}

	// sign message, ascii armored
	gpgme_set_armor( ctx, 1 );
	error = gpgme_op_sign( ctx, plain, sig, GPGME_SIG_MODE_DETACH );
	if( error ) {
		purple_debug_error( info.id, "gpgme_op_sign failed: %s %s\n", gpgme_strsource( error ), gpgme_strerror( error ) );
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
		purple_debug_error( info.id, "verify: missing sig_str\n" );
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
		purple_debug_error( info.id, "gpgme_new failed: %s %s\n", gpgme_strsource( error ), gpgme_strerror( error ) );
		return NULL;
	}

	// armor sig_str
	armored_sig_str = str_pgp_wrap( sig_str, TRUE );
	if( armored_sig_str == NULL ) {
		purple_debug_error( info.id, "str_pgp_wrap failed: could not wrap signature\n" );
		gpgme_release( ctx );
		return NULL;
	}

	// create data containers
	error = gpgme_data_new_from_mem( &sig, armored_sig_str, strlen( armored_sig_str ), 0 );
	if( error ) {
		purple_debug_error( info.id, "gpgme_data_new_from_mem failed: %s %s\n", gpgme_strsource( error ), gpgme_strerror( error ) );
		g_free( armored_sig_str );
		gpgme_release( ctx );
		return NULL;
	}
	error = gpgme_data_new( &plain );
	if( error ) {
		purple_debug_error( info.id, "gpgme_data_new failed: %s %s\n", gpgme_strsource( error ), gpgme_strerror( error ) );
		gpgme_data_release( sig );
		g_free( armored_sig_str );
		gpgme_release( ctx );
		return NULL;
	}

	// try to verify
	error = gpgme_op_verify( ctx, sig, NULL, plain );
	if( error ) {
		purple_debug_error( info.id, "gpgme_op_verify failed: %s %s\n", gpgme_strsource( error ), gpgme_strerror( error ) );
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
		purple_debug_error( info.id, "encrypt: missing ctx\n" );
		return NULL;
	}
	if( key_arr == NULL ) {
		purple_debug_error( info.id, "encrypt: missing key_arr\n" );
		return NULL;
	}
	if( plain_str == NULL ) {
		purple_debug_error( info.id, "encrypt: missing plain_str\n" );
		return NULL;
	}
	if( fpr == NULL ) {
		purple_debug_error( info.id, "encrypt: missing fpr\n" );
		return NULL;
	}

	gpgme_error_t			error;
	gpgme_data_t			plain,	cipher;
	char*					cipher_str = NULL;
	char*					cipher_str_dup = NULL;
	size_t					len;

	// connect to gpgme, if the context doesn't exist
	if( *ctx == NULL ) {
		gpgme_check_version( NULL );
		error = gpgme_new( ctx );
		if( error ) {
			purple_debug_error( info.id, "gpgme_new failed: %s %s\n", gpgme_strsource( error ), gpgme_strerror( error ) );
			return NULL;
		}
	}

	// get key by fingerprint, if it doesn't exist
	if( key_arr[ 0 ] == NULL ) {
		error = gpgme_get_key( *ctx, fpr, &key_arr[ 0 ], 0 );
		if( error || key_arr[ 0 ] == NULL ) {
			purple_debug_error( info.id, "gpgme_get_key failed: %s %s\n", gpgme_strsource( error ), gpgme_strerror( error ) );
			return NULL;
		}
	}

	// get sender key by fingerprint, if it doesn't exist
	if( key_arr[ 1 ] == NULL ) {
		// check if user selected a main key
		const char* sender_fpr = purple_prefs_get_string( PREF_MY_KEY );
		if( NULL == sender_fpr || is_empty_str( sender_fpr ) )
			purple_debug_error( info.id, "purple_prefs_get_string: PREF_MY_KEY was empty\n");
		else {
			// get own key by fingerprint
			error = gpgme_get_key( *ctx, sender_fpr, &key_arr[ 1 ], 0 );
			if( error || key_arr[ 1 ] == NULL )
				purple_debug_error( info.id, "gpgme_get_key: sender key for fingerprint %s is missing! error: %s %s\n", sender_fpr, gpgme_strsource( error ), gpgme_strerror( error ) );
		}
	}

	// create data containers
	error = gpgme_data_new_from_mem( &plain, plain_str, strlen( plain_str ), 1 );
	if( error ) {
		purple_debug_error( info.id, "gpgme_data_new_from_mem failed: %s %s\n", gpgme_strsource( error ), gpgme_strerror( error ) );
		return NULL;
	}
	error = gpgme_data_new( &cipher );
	if( error ) {
		purple_debug_error( info.id, "gpgme_data_new failed: %s %s\n", gpgme_strsource( error ), gpgme_strerror( error ) );
		gpgme_data_release( plain );
		return NULL;
	}

	// encrypt, ascii armored
	gpgme_set_armor( *ctx, 1 );
	error = gpgme_op_encrypt( *ctx, key_arr, GPGME_ENCRYPT_ALWAYS_TRUST, plain, cipher );
	if( error ) {
		purple_debug_error( info.id, "gpgme_op_encrypt failed: %s %s\n", gpgme_strsource( error ), gpgme_strerror( error ) );
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
			purple_debug_error( info.id, "str_pgp_unwrap failed, the armored message seems to be incorrect: %s\n", cipher_str );
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
static char* decrypt( const char* cipher_str ) {
	if( cipher_str == NULL ) {
		purple_debug_error( info.id, "decrypt: missing cipher_str\n" );
		return NULL;
	}

	// add header and footer:
	char* armored_buffer = str_pgp_wrap( cipher_str, FALSE );
	if( armored_buffer == NULL ) {
		purple_debug_error( info.id, "str_pgp_wrap failed: could not wrap message\n" );
		return NULL;
	}

	// connect to gpgme
	gpgme_check_version( NULL );
	gpgme_ctx_t ctx;
	gpgme_error_t error = gpgme_new( &ctx );
	if( error ) {
		purple_debug_error( info.id, "gpgme_new failed: %s %s\n", gpgme_strsource( error ), gpgme_strerror( error ) );
		g_free( armored_buffer );
		return NULL;
	}

	// create data containers
	gpgme_data_t cipher;
	error = gpgme_data_new_from_mem( &cipher, armored_buffer, strlen( armored_buffer ), 0 );
	if( error ) {
		purple_debug_error( info.id, "gpgme_data_new_from_mem failed: %s %s\n", gpgme_strsource( error ), gpgme_strerror( error ) );
		g_free( armored_buffer );
		gpgme_release( ctx );
		return NULL;
	}
	gpgme_data_t plain;
	error = gpgme_data_new( &plain );
	if( error ) {
		purple_debug_error( info.id, "gpgme_data_new failed: %s %s\n", gpgme_strsource( error ), gpgme_strerror( error ) );
		gpgme_data_release( cipher );
		g_free( armored_buffer );
		gpgme_release( ctx );
		return NULL;
	}

	// decrypt
	error = gpgme_op_decrypt( ctx, cipher, plain );
	if( error ) {
		purple_debug_error( info.id, "gpgme_op_decrypt failed: %s %s\n", gpgme_strsource( error ), gpgme_strerror( error ) );
		gpgme_data_release( cipher );
		gpgme_data_release( plain );
		g_free( armored_buffer );
		gpgme_release( ctx );
		return NULL;
	}

	// release memory for data containers
	gpgme_data_release( cipher );

	char* plain_str_dup = NULL;
	size_t len = 0;
	char* plain_str = gpgme_data_release_and_get_mem( plain, &len );
	if( plain_str != NULL ) {
		if( len > 0 ) {
			static const char encr_indicator[] = "[E] ";
			plain_str_dup = g_malloc( (sizeof(encr_indicator) - 1) + len + 1 );
			if( plain_str_dup != NULL ) {
				strcpy( plain_str_dup, encr_indicator );
				strlcpy( plain_str_dup + sizeof(encr_indicator) - 1, plain_str, len + 1 );
			}
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
	purple_debug_info( info.id, "Found gpgme version: %s\n", version );

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
	if( NULL == pc ) {
		purple_debug_error( info.id, "jabber_message_received: missing pc\n" );
		return FALSE;
	}
	if( NULL == from ) {
		purple_debug_error( info.id, "jabber_message_received: missing from\n" );
		return FALSE;
	}
	if( NULL == message ) {
		purple_debug_error( info.id, "jabber_message_received: missing message\n" );
		return FALSE;
	}

	const xmlnode* parent_node = message;

	// check if message is a key
	xmlnode* body_node = xmlnode_get_child( parent_node, "body" );
	if( body_node != NULL )	{
		char* data = xmlnode_get_data( body_node );
		if( data != NULL ) {
			static const char header[] = "-----BEGIN PGP PUBLIC KEY BLOCK-----";
			if( strncmp( data, header, sizeof( header ) - 1 ) == 0 ) {
				// if we received a ascii armored key
				// try to import it
				//purple_conversation_write(conv,"","received key",PURPLE_MESSAGE_SYSTEM | PURPLE_MESSAGE_NO_LOG,time(NULL));
				xmlnode_clear_data( body_node );
				xmlnode_insert_data( body_node,
					(import_key( data ))
						? "key import ok"
						: "key import failed",
					-1 );
			} else if( xmlnode_get_child_with_namespace( parent_node, "x", NS_ENC ) == NULL ) { // unencrypted message
				xmlnode_clear_data( body_node );
				xmlnode_insert_data( body_node, "[Open!!!] ", -1 );
				xmlnode_insert_data( body_node, data, -1 );
			}

			g_free(data);
		}
	}

	// check if message has special "x" child node => encrypted message
	xmlnode* x_node = xmlnode_get_child_with_namespace( parent_node, "x", NS_ENC );
	if( NULL == x_node )
		return FALSE;

	purple_debug_info( info.id, "user %s sent us an encrypted message\n", from );

	// get data of "x" node
	char* cipher_str = xmlnode_get_data( x_node );
	if( NULL == cipher_str ) {
		purple_debug_error( info.id, "xml token had no data!\n" );
		return FALSE;
	}

	// try to decrypt
	char* plain_str = decrypt( cipher_str );
	if( NULL == plain_str ) {
		purple_debug_error( info.id, "could not decrypt message!\n" );
		goto l_free_cipher_str;
	}

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
	g_free( plain_str );
l_free_cipher_str:
	g_free( cipher_str );
	// We don't want the plugin to stop processing
	return FALSE;
}

/* ------------------
 * called on received presence
 * ------------------ */
static gboolean jabber_presence_received( PurpleConnection* pc, const char* type, const char* from, const xmlnode* presence ) {
	if( NULL == from ) {
		purple_debug_error( info.id, "jabber_presence_received: missing from\n" );
		return FALSE;
	}
	if( NULL == presence ) {
		purple_debug_error( info.id, "jabber_presence_received: missing presence\n" );
		return FALSE;
	}

	// check if presence has special "x" childnode
	const xmlnode* x_node = xmlnode_get_child_with_namespace( presence, "x", NS_SIGNED );
	if( NULL == x_node )
		return FALSE;
	// user supports openpgp encryption
	purple_debug_info( info.id, "user %s supports openpgp encryption!\n", from );

	char* x_node_data = xmlnode_get_data( x_node );
	if( NULL == x_node_data )
		purple_debug_info( info.id, "user %s sent empty signed presence\n", from );
	else {
		// try to verify
		char* fpr = verify( x_node_data );
		if( NULL == fpr )
			purple_debug_error( info.id, "could not verify presence of user %s\n", from );
		else {
			purple_debug_info( info.id, "user %s has fingerprint %s\n", from, fpr );
			g_free(fpr);
		}

		g_free(x_node_data);
	}

	// We don't want the plugin to stop processing
	return FALSE;
}

/* ------------------
 * is it necessary to encrypt outgoing messages?
 * ------------------ */
static gboolean is_encr_enabled( PurpleConversation* conv ) {
	GtkToggleButton* tb = GTK_TOGGLE_BUTTON( purple_conversation_get_data( conv, GPG_CHECK_BTN_ENCR_ENABLED ) );
	if( NULL == tb ) {
		purple_debug_info( info.id, "jabber_send_signal_cb: purple_conversation_get_data failed\n" );
		return FALSE;
	}

	return gtk_toggle_button_get_active( tb );
}

/* ------------------
 * called on every sent packet
 * ------------------ */
static void jabber_send_signal_cb( PurpleConnection* pc, xmlnode** packet, gpointer unused ) {
	if( packet == NULL ) {
		purple_debug_error( info.id, "jabber_send_signal_cb: missing packet\n" );
		return;
	}

	g_return_if_fail( PURPLE_CONNECTION_IS_VALID( pc ) );

	// if we are sending a presence stanza, add new child node
	//  so others know we support openpgp
	if( g_str_equal( (*packet)->name, "presence" ) ) {
		// check if user selected a main key
		const char* fpr = purple_prefs_get_string( PREF_MY_KEY );
		if( NULL == fpr || is_empty_str( fpr ) )
			purple_debug_info( info.id, "no key selected!\n" );
		else {
			// user did select a key
			// get status message from packet
			xmlnode* status_node = xmlnode_get_child( *packet, "status" );
			char* status_str = ( NULL == status_node ) ? NULL : xmlnode_get_data( status_node );
			// sign status message
			const char* status_str2 = ( NULL == status_str ) ? "" : status_str;
			purple_debug_info( info.id, "signing status '%s' with key %s\n", status_str2, fpr );

			char* sig_str = sign( status_str2, fpr );
			if( sig_str == NULL ) {
				purple_debug_error( info.id, "sign failed\n" );
				return;
			}

			// create special "x" childnode
			purple_debug_info( info.id, "sending presence with signature\n" );
			xmlnode* x_node = xmlnode_new_child( *packet, "x" );
			xmlnode_set_namespace( x_node, NS_SIGNED );
			xmlnode_insert_data( x_node, sig_str, -1 );
			g_free( sig_str );
			g_free( status_str );
		}
	} else if( g_str_equal( (*packet)->name, "message" ) ) {
		const char* to = xmlnode_get_attrib( *packet, "to" );
		xmlnode* body_node = xmlnode_get_child( *packet, "body" );
		if( NULL == body_node || NULL == to )
			return; // ignore this type of messages

		PurpleConversation* conv = purple_find_conversation_with_account( PURPLE_CONV_TYPE_IM, to, pc->account );
		if( NULL == conv ) {
			purple_debug_info( info.id, "jabber_send_signal_cb: purple_find_conversation_with_account failed\n" );
			return;
		}

		if( !is_encr_enabled( conv ) ) {
			purple_debug_info( info.id, "jabber_send_signal_cb: Encryption disabled\n" );
			return;
		}

		// get message
		char* message = xmlnode_get_data( body_node );
		if( NULL == message ) {
			purple_debug_info( info.id, "jabber_send_signal_cb: xmlnode_get_data( body_node ) failed\n" );
			return;
		}

		char* bare_jid = get_bare_jid( to );
		if( NULL == bare_jid ) {
			purple_debug_info( info.id, "jabber_send_signal_cb: get_bare_jid failed for %s\n", to );
			g_free( message );
			return;
		}

		// get encryption key
		struct list_item* item = g_hash_table_lookup( list_fingerprints, bare_jid );
		if( NULL == item ) {
			purple_debug_info( info.id, "there is no key for encrypting message to %s\n", bare_jid );
			g_free( message );
			g_free( bare_jid );
			return;
		}

		purple_debug_info( info.id, "found key for encryption to user %s: %s\n", bare_jid, item->fpr );
		g_free( bare_jid );

		// encrypt message
		char* enc_str = encrypt( &item->ctx, item->key_arr, message, item->fpr );
		g_free( message );
		if( NULL == enc_str ) {
			purple_debug_error( info.id, "could not encrypt message\n" );
			return;
		}
		// remove message from body
		xmlnode_clear_data( body_node );
		xmlnode_insert_data( body_node, "[ERROR: This message is encrypted, and you are unable to decrypt it.]" , -1 );

		// add special "x" childnode for encrypted text
		purple_debug_info( info.id, "sending encrypted message\n" );
		xmlnode* x_node = xmlnode_new_child( *packet, "x" );
		xmlnode_set_namespace( x_node, NS_ENC );
		xmlnode_insert_data( x_node, enc_str, -1 );
		g_free( enc_str );
	}
}

/* ------------------
 * send public key to other person in conversation
 * ------------------ */
static void menu_action_sendkey_cb( PurpleConversation* conv, void* data ) {
	// check if user selected a main key
	const char* fpr = purple_prefs_get_string( PREF_MY_KEY );
	if( NULL == fpr || is_empty_str( fpr ) ) {
		purple_conversation_write( conv, "", "You haven't selected a personal key yet.", PURPLE_MESSAGE_SYSTEM | PURPLE_MESSAGE_NO_LOG, time( NULL ) );
		return;
	}

	// get key
	char* key = get_key_armored( fpr );
	if( NULL == key )
		return;

	// send key
	PurpleConvIm* im_data = purple_conversation_get_im_data( conv );
	if( im_data != NULL ) {
		purple_conv_im_send_with_flags( im_data, key, PURPLE_MESSAGE_SYSTEM | PURPLE_MESSAGE_INVISIBLE | PURPLE_MESSAGE_RAW );
		purple_conversation_write( conv, "", "Public key sent!", PURPLE_MESSAGE_SYSTEM | PURPLE_MESSAGE_NO_LOG, time( NULL ) );
	}

	g_free( key );
}

/* ------------------
 * conversation extended menu
 * ------------------ */
void conversation_extended_menu_cb( PurpleConversation* conv, GList** list ) {
	if( NULL == conv ) {
		purple_debug_error( info.id, "conversation_extended_menu_cb: missing conv\n" );
		return;
	}
	if( NULL == list ) {
		purple_debug_error( info.id, "conversation_extended_menu_cb: missing list\n" );
		return;
	}

	const char* fpr = purple_prefs_get_string( PREF_MY_KEY );
	if( fpr != NULL && !is_empty_str( fpr ) ) {
		char buffer[ 200 ];
		snprintf( buffer, sizeof( buffer ), "Send own public key to '%s'", conv->name );
		*list = g_list_append( *list,
			purple_menu_action_new( buffer, PURPLE_CALLBACK( menu_action_sendkey_cb ), NULL, NULL ) );
	}
}


static void check_bnt_enabled_toggled( GtkWidget *widget, PurpleConversation *conv ) {
	// tell user, that we toggled mode
	purple_conversation_write( conv, "",
		gtk_toggle_button_get_active( GTK_TOGGLE_BUTTON( widget ) ) ? "Encryption enabled" : "Encryption disabled",
		PURPLE_MESSAGE_SYSTEM | PURPLE_MESSAGE_NO_LOG, time( NULL ) );
}

static void pub_key_selected_cb( GtkCheckMenuItem *checkmenuitem, PurpleConversation *conv) {
	char* bare_jid = get_bare_jid( conv->name );
	if( g_hash_table_lookup( list_fingerprints, bare_jid ) != NULL )
		g_hash_table_remove( list_fingerprints, bare_jid );

	PurpleBuddy *buddy = purple_find_buddy( purple_conversation_get_account( conv ), conv->name );
	if( NULL == buddy ) {
		purple_debug_error( info.id, "buddy %s not found\n", conv->name );
		g_free( bare_jid );
		return;
	}

	const char* cur_value = purple_blist_node_get_string( &buddy->node, PREF_PUB_KEY_FPR );
	const char* lbl = gtk_menu_item_get_label( GTK_MENU_ITEM(checkmenuitem) );
	const char* last_space = strrchr( lbl, ' ' );
	if (NULL == last_space) {
		g_free( bare_jid );
		return;
	}

	const char* new_value = last_space + 1;
	GtkWidget* check_bnt = (GtkWidget*)purple_conversation_get_data( conv, GPG_CHECK_BTN_ENCR_ENABLED );
	if( cur_value != NULL && g_str_equal( new_value, cur_value ) ) {
		purple_blist_node_remove_setting( &buddy->node, PREF_PUB_KEY_FPR );
		g_free( bare_jid );
		gtk_toggle_button_set_active( GTK_TOGGLE_BUTTON( check_bnt ), FALSE );
		gtk_widget_set_sensitive( check_bnt, FALSE );
	} else {
		gtk_toggle_button_set_active( GTK_TOGGLE_BUTTON( check_bnt ), TRUE );
		gtk_widget_set_sensitive( check_bnt, TRUE );
		purple_blist_node_set_string( &buddy->node, PREF_PUB_KEY_FPR, new_value );
		list_fingerprints_add( bare_jid, g_strdup( new_value ) );
	}
}

static gboolean pub_key_bnt_pressed( GtkWidget *w, GdkEventButton *event, PurpleConversation *conv ) {
	/* Any button will do */
	if( event->type != GDK_BUTTON_PRESS )
		return FALSE;

	// connect to gpgme
	gpgme_check_version( NULL );
	gpgme_ctx_t ctx;
	gpgme_error_t error = gpgme_new( &ctx );
	if( error ) {
		purple_debug_error( info.id, "gpgme_new failed: %s %s\n", gpgme_strsource( error ), gpgme_strerror( error ) );
		return TRUE;
	}

	// list public keys
	error = gpgme_op_keylist_start( ctx, NULL, 0 );
	if( error != GPG_ERR_NO_ERROR ) {
		purple_debug_error( info.id, "gpgme_op_keylist_start failed: %s %s\n", gpgme_strsource( error ), gpgme_strerror( error ) );
		return TRUE;
	}

	PurpleBuddy *buddy = purple_find_buddy( purple_conversation_get_account( conv ), conv->name );
	if( NULL == buddy ) {
		purple_debug_error( info.id, "buddy %s not found\n", conv->name );
		return TRUE;
	}

	GtkWidget *menu = gtk_menu_new();
	const char* pub_key_fpr = purple_blist_node_get_string( &buddy->node, PREF_PUB_KEY_FPR );
	gpgme_key_t key;
	while( gpgme_op_keylist_next( ctx, &key ) == GPG_ERR_NO_ERROR ) {
		if( key->can_encrypt && key->can_sign )
		{
			// Add menu item
			char label[100];
			// fingerprint will be used in pub_key_selected_cb from label. So label format matters
			snprintf( label, sizeof(label), "%s %s", key->uids->uid, key->subkeys->fpr );

			GtkWidget* memu_item = gtk_check_menu_item_new_with_label( label );
			gtk_check_menu_item_set_active( GTK_CHECK_MENU_ITEM( memu_item ),
					(pub_key_fpr != NULL && g_str_equal(key->subkeys->fpr, pub_key_fpr)) );
			g_signal_connect( G_OBJECT( memu_item ), "toggled", G_CALLBACK(pub_key_selected_cb), conv );
			gtk_menu_shell_append( GTK_MENU_SHELL( menu ), memu_item );
		}

		gpgme_key_release( key );
	}

	gtk_widget_show_all( menu );
	gtk_menu_popup( GTK_MENU(menu), NULL, NULL, NULL, NULL, 3, event->time );
	return TRUE;
}

/* If the conversation switches on us */
static void conversation_switched( PurpleConversation *conv, void * data ) {
	if( conv == NULL
		|| purple_conversation_get_type(conv) != PURPLE_CONV_TYPE_IM)
		return;

	PidginConversation *gtkconv = PIDGIN_CONVERSATION(conv);
	GtkWidget *check_bnt = purple_conversation_get_data(conv, GPG_CHECK_BTN_ENCR_ENABLED);
	if( check_bnt != NULL ) {
		GList *children = gtk_container_get_children(GTK_CONTAINER(gtkconv->toolbar));
		if( !g_list_find(children, check_bnt) )
			gtk_box_pack_start(GTK_BOX(gtkconv->toolbar), check_bnt, FALSE, FALSE, 0);
		g_list_free(children);
		gtk_widget_show_all(check_bnt);
		return;
	}

	// conversation is created
	check_bnt = gtk_check_button_new_with_label("GPG encryption");
	gtk_box_pack_start(GTK_BOX(gtkconv->toolbar), check_bnt, FALSE, FALSE, 0);
	gtk_widget_show_all(check_bnt);
	purple_conversation_set_data(conv, GPG_CHECK_BTN_ENCR_ENABLED, check_bnt);

	// check if the user with the jid=conv->name has signed his presence
	char* bare_jid = get_bare_jid( conv->name );
	if( NULL == bare_jid ) {
		purple_debug_info( info.id, "conversation_switched: get_bare_jid failed for %s\n", conv->name );
		return;
	}

	purple_debug_info( info.id, "conversation name: %s bare jid: %s\n", conv->name, bare_jid );

	// get stored info about user
	char sys_msg_buffer[1000];
	PurpleBuddy *buddy = purple_find_buddy( purple_conversation_get_account( conv ), bare_jid );
	if( NULL == buddy )
		snprintf( sys_msg_buffer, sizeof( sys_msg_buffer ), "buddy %s not found\n", bare_jid );
	else {
		const char* pub_key_fpr = purple_blist_node_get_string( &buddy->node, PREF_PUB_KEY_FPR );
		if( NULL == pub_key_fpr ) {
			strcpy( sys_msg_buffer, "Encryption is not possible. Set public key for the remote client." );
			gtk_widget_set_sensitive( check_bnt, FALSE );
		} else {
			if( g_hash_table_lookup( list_fingerprints, bare_jid ) != NULL )
				g_hash_table_remove( list_fingerprints, bare_jid );
			list_fingerprints_add( g_strdup( bare_jid ), g_strdup( pub_key_fpr ) );
			struct list_item* item = g_hash_table_lookup( list_fingerprints, bare_jid );
			if( item != NULL ) {
				// check if we have key locally
				char *userid = NULL;
				if( is_key_available( &item->ctx, item->key_arr, item->fpr, FALSE, FALSE, &userid ) == FALSE ) {
					// local key is missing
					snprintf( sys_msg_buffer, sizeof( sys_msg_buffer ), "User has key with Fingerprint %s, but we do not have it locally. Try Options -> \"Try to retrieve key of '%s' from server\"", item->fpr, bare_jid );
					gtk_widget_set_sensitive( check_bnt, FALSE );
				} else {
					// key is already available locally -> enable mode_enc
					snprintf( sys_msg_buffer, sizeof( sys_msg_buffer ), "Encryption enabled with %s (%s)", userid, item->fpr );
					gtk_toggle_button_set_active( GTK_TOGGLE_BUTTON( check_bnt ), TRUE );
				}
				if( userid != NULL )
					g_free( userid );
			}
		}
	}

	// display message about received message
	purple_conversation_write( conv, "", sys_msg_buffer, PURPLE_MESSAGE_SYSTEM | PURPLE_MESSAGE_NO_LOG, time( NULL ) );

	// release resources
	g_free( bare_jid );

	// after gtk_toggle_button_set_active to avoid two messages
	g_signal_connect (check_bnt, "toggled", G_CALLBACK (check_bnt_enabled_toggled), conv);

	GtkWidget* pub_key_bnt = gtk_button_new_with_label( "Select GPG pub key" );
	gtk_box_pack_start( GTK_BOX( gtkconv->toolbar ), pub_key_bnt, FALSE, FALSE, 0 );
	g_signal_connect( G_OBJECT( pub_key_bnt ), "button-press-event", G_CALLBACK(pub_key_bnt_pressed), conv );
	gtk_widget_show( pub_key_bnt );
}

/* ------------------
 * called on module load
 * ------------------ */
static gboolean plugin_load( PurplePlugin* plugin ) {
	// check if hashtable already created
	if( list_fingerprints == NULL )
		list_fingerprints = g_hash_table_new_full( g_str_hash, g_str_equal, g_free, list_item_destroy );

	// register presence receiver handler

	{
	void *conv_handle = purple_conversations_get_handle();
	if( NULL == conv_handle )
		return FALSE;
	purple_signal_connect( conv_handle, "conversation-extended-menu",	plugin, PURPLE_CALLBACK( conversation_extended_menu_cb ),	NULL );
	}

	{
	void *jabber_handle = purple_plugins_find_with_id( "prpl-jabber" );
	if( NULL == jabber_handle )
		return FALSE;
	purple_signal_connect( jabber_handle, "jabber-receiving-message",	plugin, PURPLE_CALLBACK( jabber_message_received ),			NULL );
	purple_signal_connect( jabber_handle, "jabber-receiving-presence",	plugin, PURPLE_CALLBACK( jabber_presence_received ),		NULL );
	purple_signal_connect( jabber_handle, "jabber-sending-xmlnode",		plugin, PURPLE_CALLBACK( jabber_send_signal_cb ),			NULL );
	}

	purple_signal_connect(pidgin_conversations_get_handle(), "conversation-switched", plugin, PURPLE_CALLBACK(conversation_switched), NULL);

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
		purple_debug_error( info.id, "gpgme_new failed: %s %s\n", gpgme_strsource( error ), gpgme_strerror( error ) );
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
			purple_debug_info( info.id, "Found secret key for: %s has fpr %s\n", key->uids->uid, key->subkeys->fpr );
			gpgme_key_release( key );
		}
	} else
		purple_debug_error( info.id, "gpgme_op_keylist_start failed: %s %s\n", gpgme_strsource( error ), gpgme_strerror( error ) );

	// release resources
	gpgme_release( ctx );

	// add the frame
	purple_plugin_pref_frame_add( frame, ppref );

	return frame;
}

/* ------------------
 * plugin init
 * ------------------ */
static void init_plugin( PurplePlugin *plugin ) {
	// create entries in prefs if they are not there
	purple_prefs_add_none( PREF_ROOT );
	purple_prefs_add_string( PREF_MY_KEY, "" );
}

PURPLE_INIT_PLUGIN( pidgin-gpg, init_plugin, info )
