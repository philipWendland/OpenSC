/*
 * Support for the IsoApplet JavaCard Applet.
 * IsoApplet Version 0 for smart cards with JavaCard version 2.2.2.
 *
 * Copyright (C) 2020 Philip Wendland <philip@wendland.xyz>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <stdlib.h>
#include <string.h>

#include "asn1.h"
#include "cardctl.h"
#include "internal.h"
#include "log.h"
#include "opensc.h"
#include "pkcs15.h"
#include "types.h"
#include "card-isoapplet-common.h"


#define ISOAPPLET_API_VERSION_MAJOR 0x00
#define ISOAPPLET_API_VERSION_MINOR 0x06

#define ISOAPPLET_API_FEATURE_EXT_APDU 0x01
#define ISOAPPLET_API_FEATURE_SECURE_RANDOM 0x02
#define ISOAPPLET_API_FEATURE_ECC 0x04

#define ISOAPPLET_AID_LEN 12
static const u8 isoapplet0_aid[] = {0xf2,0x76,0xa2,0x88,0xbc,0xfb,0xa6,0x9d,0x34,0xf3,0x10,0x01};

static struct isoapplet_supported_ec_curves ec_curves[] = {
	{{{1, 2, 840, 10045, 3, 1, 1, -1}},     192, 0x0000}, /* secp192r1, nistp192, prime192v1, ansiX9p192r1 */
	{{{1, 3, 132, 0, 33, -1}},              224, 0x0000}, /* secp224r1, nistp224 */
	{{{1, 2, 840, 10045, 3, 1, 7, -1}},     256, 0x0000}, /* secp256r1, nistp256, prime256v1, ansiX9p256r1 */
	{{{1, 3, 132, 0, 34, -1}},              384, 0x0000}, /* secp384r1, nistp384, prime384v1, ansiX9p384r1 */
	{{{1, 3, 36, 3, 3, 2, 8, 1, 1, 3, -1}}, 192, 0x0000}, /* brainpoolP192r1 */
	{{{1, 3, 36, 3, 3, 2, 8, 1, 1, 5, -1}}, 224, 0x0000}, /* brainpoolP224r1 */
	{{{1, 3, 36, 3, 3, 2, 8, 1, 1, 7, -1}}, 256, 0x0000}, /* brainpoolP256r1 */
	{{{1, 3, 36, 3, 3, 2, 8, 1, 1, 9, -1}}, 320, 0x0000}, /* brainpoolP320r1 */
	{{{1, 3, 132, 0, 31, -1}},              192, 0x0006}, /* secp192k1 */
	{{{1, 3, 132, 0, 10, -1}},              256, 0x0006}, /* secp256k1 */
	{{{-1}}, 0, 0} /* This entry must not be touched. */
};

/* Operations supported by the applet. */
static struct sc_card_operations isoapplet0_ops;

/* A reference to the iso7816_* functions.
 * Initialized in sc_get_driver. */
static const struct sc_card_operations *iso_ops = NULL;

/* The description of the driver. */
static struct sc_card_driver isoapplet0_drv =
{
	"Javacard with IsoApplet v0.x",
	"isoapplet0",
	&isoapplet0_ops,
	NULL, 0, NULL
};

/*
 * SELECT an applet on the smartcard. (Not in the emulated filesystem.)
 * The response will be written to resp.
 *
 * @param[in]     card
 * @param[in]     aid      The applet ID.
 * @param[in]     aid_len  The length of aid.
 * @param[out]    resp     The response of the applet upon selection.
 * @param[in,out] resp_len In: The buffer size of resp. Out: The length of the response.
 *
 * @return SC_SUCCESS: The applet is present and could be selected.
 *         any other:  Transmit failure or the card returned an error.
 *                     The card will return an error when the applet is
 *                     not present.
 */
static int
isoapplet0_select_applet(sc_card_t *card, const u8 *aid, const size_t aid_len, u8 *resp, size_t *resp_len)
{
	int rv;
	sc_context_t *ctx = card->ctx;
	sc_apdu_t apdu;

	LOG_FUNC_CALLED(card->ctx);

	if(aid_len > SC_MAX_APDU_BUFFER_SIZE)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_BUFFER_TOO_SMALL);

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xa4, 0x04, 0x00);
	apdu.lc = aid_len;
	apdu.data = aid;
	apdu.datalen = aid_len;
	apdu.resp = resp;
	apdu.resplen = *resp_len;
	apdu.le = 0;

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU transmit failure.");

	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, rv, "Card returned error");

	*resp_len = apdu.resplen;
	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int
isoapplet0_match_card(sc_card_t *card)
{
	size_t rlen = SC_MAX_APDU_BUFFER_SIZE;
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
	int rv;

	rv = isoapplet0_select_applet(card, isoapplet0_aid, ISOAPPLET_AID_LEN, rbuf, &rlen);

	if(rv != SC_SUCCESS)
	{
		return 0;
	}

	/* The IsoApplet should return an API version (major and minor) and a feature bitmap.
	 * We expect 3 bytes: MAJOR API version - MINOR API version - API feature bitmap.
	 * If applet does not return API version, versions 0x00 will match */
	if(rlen < 3)
	{
		assert(sizeof(rbuf) >= 3);
		memset(rbuf, 0x00, 3);
	}

	if(rbuf[0] != ISOAPPLET_API_VERSION_MAJOR)
	{
		sc_log(card->ctx, "IsoApplet: Mismatching major API version. Not proceeding. "
		       "API versions: Driver (%02X-%02X), applet (%02X-%02X). Please update accordingly.",
		       ISOAPPLET_API_VERSION_MAJOR, ISOAPPLET_API_VERSION_MINOR, rbuf[0], rbuf[1]);
		return 0;
	}

	if(rbuf[1] != ISOAPPLET_API_VERSION_MINOR)
	{
		sc_log(card->ctx, "IsoApplet: Mismatching minor API version. Proceeding anyway. "
		       "API versions: Driver (%02X-%02X), applet (%02X-%02X). "
		       "Please update accordingly whenever possible.",
		       ISOAPPLET_API_VERSION_MAJOR, ISOAPPLET_API_VERSION_MINOR, rbuf[0], rbuf[1]);
	}

	return 1;
}

static int
isoapplet0_init(sc_card_t *card)
{
	int i;
	unsigned long flags = 0;
	unsigned long ext_flags = 0;
	size_t rlen = SC_MAX_APDU_BUFFER_SIZE;
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
	struct isoapplet_drv_data *drvdata;

	LOG_FUNC_CALLED(card->ctx);

	drvdata=calloc(1, sizeof(*drvdata));
	if (!drvdata)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);

	card->drv_data = drvdata;
	card->cla = 0x00;

	/* Obtain applet version and specific features */
	if (0 > isoapplet0_select_applet(card, isoapplet0_aid, ISOAPPLET_AID_LEN, rbuf, &rlen)) {
		free(card->drv_data);
		card->drv_data = NULL;
		LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_CARD, "Error obtaining applet version.");
	}
	if(rlen < 3)
	{
		assert(sizeof(rbuf) >= 3);
		memset(rbuf, 0x00, 3);
	}
	drvdata->isoapplet_version = ((unsigned int)rbuf[0] << 8) | rbuf[1];
	if(rbuf[2] & ISOAPPLET_API_FEATURE_EXT_APDU)
		card->caps |=  SC_CARD_CAP_APDU_EXT;
	if(rbuf[2] & ISOAPPLET_API_FEATURE_SECURE_RANDOM)
		card->caps |=  SC_CARD_CAP_RNG;
	if(drvdata->isoapplet_version <= 0x0005 || rbuf[2] & ISOAPPLET_API_FEATURE_ECC)
	{
		/* There are Java Cards that do not support ECDSA at all. The IsoApplet
		 * started to report this with version 00.06.
		 *
		 * Curves supported by the pkcs15-init driver are indicated per curve. This
		 * should be kept in sync with the explicit parameters in the pkcs15-init
		 * driver. */
		flags = 0;
		flags |= SC_ALGORITHM_ECDSA_RAW;
		flags |= SC_ALGORITHM_ECDSA_HASH_SHA1;
		flags |= SC_ALGORITHM_ONBOARD_KEY_GEN;
		ext_flags = SC_ALGORITHM_EXT_EC_UNCOMPRESES;
		ext_flags |=  SC_ALGORITHM_EXT_EC_NAMEDCURVE;
		ext_flags |= SC_ALGORITHM_EXT_EC_F_P;
		for (i=0; ec_curves[i].oid.value[0] >= 0; i++)
		{
			if(drvdata->isoapplet_version >= ec_curves[i].min_applet_version)
				_sc_card_add_ec_alg(card, ec_curves[i].size, flags, ext_flags, &ec_curves[i].oid);
		}
	}

	/* RSA */
	flags = 0;
	/* Padding schemes: */
	flags |= SC_ALGORITHM_RSA_PAD_PKCS1;
	/* Hashes are to be done by the host for RSA */
	flags |= SC_ALGORITHM_RSA_HASH_NONE;
	/* Key-generation: */
	flags |= SC_ALGORITHM_ONBOARD_KEY_GEN;
	/* Modulus lengths: */
	_sc_card_add_rsa_alg(card, 2048, flags, 0);

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

int isoapplet0_card_reader_lock_obtained(sc_card_t *card, int was_reset)
{
	int r = SC_SUCCESS;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	if (was_reset > 0) {
		size_t rlen = SC_MAX_APDU_BUFFER_SIZE;
		u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
		r = isoapplet0_select_applet(card, isoapplet0_aid, ISOAPPLET_AID_LEN, rbuf, &rlen);
	}

	LOG_FUNC_RETURN(card->ctx, r);
}

static struct sc_card_driver *sc_get_driver(void)
{
	sc_card_driver_t *iso_drv = sc_get_iso7816_driver();

	if(iso_ops == NULL)
	{
		iso_ops = iso_drv->ops;
	}

	isoapplet0_ops = *iso_drv->ops;

	isoapplet0_ops.match_card = isoapplet0_match_card;
	isoapplet0_ops.init = isoapplet0_init;
	isoapplet0_ops.finish = isoapplet_finish;

	isoapplet0_ops.card_ctl = isoapplet_card_ctl;

	isoapplet0_ops.create_file = isoapplet_create_file;
	isoapplet0_ops.process_fci = isoapplet_process_fci;
	isoapplet0_ops.set_security_env = isoapplet_set_security_env;
	isoapplet0_ops.compute_signature = isoapplet_compute_signature;
	isoapplet0_ops.get_challenge = isoapplet_get_challenge;
	isoapplet0_ops.card_reader_lock_obtained = isoapplet0_card_reader_lock_obtained;

	/* unsupported functions */
	isoapplet0_ops.write_binary = NULL;
	isoapplet0_ops.read_record = NULL;
	isoapplet0_ops.write_record = NULL;
	isoapplet0_ops.append_record = NULL;
	isoapplet0_ops.update_record = NULL;
	isoapplet0_ops.restore_security_env = NULL;

	return &isoapplet0_drv;
}

struct sc_card_driver * sc_get_isoapplet0_driver(void)
{
	return sc_get_driver();
}

