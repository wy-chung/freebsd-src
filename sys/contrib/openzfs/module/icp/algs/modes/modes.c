/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or https://opensource.org/licenses/CDDL-1.0.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/zfs_context.h>
#include <modes/modes.h>
#include <sys/crypto/common.h>
#include <sys/crypto/impl.h>

/*
 * Initialize by setting iov_or_mp to point to the current iovec or mp,
 * and by setting current_offset to an offset within the current iovec or mp.
 */
void
crypto_init_ptrs(crypto_data_t *out, void **iov_or_mp, offset_t *current_offset)
{
	offset_t offset;

	switch (out->cd_format) {
	case CRYPTO_DATA_RAW:
		*current_offset = out->cd_offset;
		break;

	case CRYPTO_DATA_UIO: {
		zfs_uio_t *uiop = out->cd_uio;
		uint_t vec_idx;

		offset = out->cd_offset;
		offset = zfs_uio_index_at_offset(uiop, offset, &vec_idx);

		*current_offset = offset;
		*iov_or_mp = (void *)(uintptr_t)vec_idx;
		break;
	}
	} /* end switch */
}

/*
 * Get pointers for where in the output to copy a block of encrypted or
 * decrypted data.  The iov_or_mp argument stores a pointer to the current
 * iovec or mp, and offset stores an offset into the current iovec or mp.
 */
void
crypto_get_ptrs(crypto_data_t *out, void **iov_or_mp, offset_t *current_offset,
    uint8_t **out_data_1, size_t *out_data_1_len, uint8_t **out_data_2,
    size_t amt)
{
	offset_t offset;

	switch (out->cd_format) {
	case CRYPTO_DATA_RAW: {
		iovec_t *iov;

		offset = *current_offset;
		iov = &out->cd_raw;
		if ((offset + amt) <= iov->iov_len) {
			/* one block fits */
			*out_data_1 = (uint8_t *)iov->iov_base + offset;
			*out_data_1_len = amt;
			*out_data_2 = NULL;
			*current_offset = offset + amt;
		}
		break;
	}

	case CRYPTO_DATA_UIO: {
		zfs_uio_t *uio = out->cd_uio;
		offset_t offset;
		uint_t vec_idx;
		uint8_t *p;
		uint64_t iov_len;
		void *iov_base;

		offset = *current_offset;
		vec_idx = (uintptr_t)(*iov_or_mp);
		zfs_uio_iov_at_index(uio, vec_idx, &iov_base, &iov_len);
		p = (uint8_t *)iov_base + offset;
		*out_data_1 = p;

		if (offset + amt <= iov_len) {
			/* can fit one block into this iov */
			*out_data_1_len = amt;
			*out_data_2 = NULL;
			*current_offset = offset + amt;
		} else {
			/* one block spans two iovecs */
			*out_data_1_len = iov_len - offset;
			if (vec_idx == zfs_uio_iovcnt(uio)) {
				*out_data_2 = NULL;
				return;
			}
			vec_idx++;
			zfs_uio_iov_at_index(uio, vec_idx, &iov_base, &iov_len);
			*out_data_2 = (uint8_t *)iov_base;
			*current_offset = amt - *out_data_1_len;
		}
		*iov_or_mp = (void *)(uintptr_t)vec_idx;
		break;
	}
	} /* end switch */
}

void
crypto_free_mode_ctx(void *ctx)
{
	common_ctx_t *common_ctx = (common_ctx_t *)ctx;

	switch (common_ctx->cc_flags &
	    (ECB_MODE|CBC_MODE|CTR_MODE|CCM_MODE|GCM_MODE|GMAC_MODE)) {
	case ECB_MODE:
		kmem_free(common_ctx, sizeof (ecb_ctx_t));
		break;

	case CBC_MODE:
		kmem_free(common_ctx, sizeof (cbc_ctx_t));
		break;

	case CTR_MODE:
		kmem_free(common_ctx, sizeof (ctr_ctx_t));
		break;

	case CCM_MODE:
		if (((ccm_ctx_t *)ctx)->ccm_pt_buf != NULL)
			vmem_free(((ccm_ctx_t *)ctx)->ccm_pt_buf,
			    ((ccm_ctx_t *)ctx)->ccm_data_len);

		kmem_free(ctx, sizeof (ccm_ctx_t));
		break;

	case GCM_MODE:
	case GMAC_MODE:
		gcm_clear_ctx((gcm_ctx_t *)ctx);
		kmem_free(ctx, sizeof (gcm_ctx_t));
	}
}

static void *
explicit_memset(void *s, int c, size_t n)
{
	memset(s, c, n);
	__asm__ __volatile__("" :: "r"(s) : "memory");
	return (s);
}

/*
 * Clear sensitive data in the context and free allocated memory.
 *
 * ctx->gcm_remainder may contain a plaintext remainder. ctx->gcm_H and
 * ctx->gcm_Htable contain the hash sub key which protects authentication.
 * ctx->gcm_pt_buf contains the plaintext result of decryption.
 *
 * Although extremely unlikely, ctx->gcm_J0 and ctx->gcm_tmp could be used for
 * a known plaintext attack, they consist of the IV and the first and last
 * counter respectively. If they should be cleared is debatable.
 */
void
gcm_clear_ctx(gcm_ctx_t *ctx)
{
	explicit_memset(ctx->gcm_remainder, 0, sizeof (ctx->gcm_remainder));
	explicit_memset(ctx->gcm_H, 0, sizeof (ctx->gcm_H));
#if defined(CAN_USE_GCM_ASM)
	if (ctx->gcm_use_avx == B_TRUE) {
		ASSERT3P(ctx->gcm_Htable, !=, NULL);
		explicit_memset(ctx->gcm_Htable, 0, ctx->gcm_htab_len);
		kmem_free(ctx->gcm_Htable, ctx->gcm_htab_len);
	}
#endif
	if (ctx->gcm_pt_buf != NULL) {
		explicit_memset(ctx->gcm_pt_buf, 0, ctx->gcm_pt_buf_len);
		vmem_free(ctx->gcm_pt_buf, ctx->gcm_pt_buf_len);
	}
	/* Optional */
	explicit_memset(ctx->gcm_J0, 0, sizeof (ctx->gcm_J0));
	explicit_memset(ctx->gcm_tmp, 0, sizeof (ctx->gcm_tmp));
}
