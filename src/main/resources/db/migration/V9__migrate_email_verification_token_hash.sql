-- 1. Tambahkan kolom baru
ALTER TABLE email_verification_tokens
ADD COLUMN token_hash VARCHAR(64);

-- 2. Migrasi token lama menjadi SHA-256 hash
-- Token UUID diubah menjadi string sebelum di-hash.
UPDATE email_verification_tokens
SET token_hash = encode(
    sha256(convert_to(token::TEXT, 'UTF8')),
    'hex'
);

-- 3. Pastikan seluruh record memiliki hash
ALTER TABLE email_verification_tokens
ALTER COLUMN token_hash SET NOT NULL;

-- 4. Pastikan token hash unik
ALTER TABLE email_verification_tokens
ADD CONSTRAINT uq_email_verification_token_hash
UNIQUE (token_hash);

-- 5. Hapus token mentah
ALTER TABLE email_verification_tokens
DROP COLUMN token;