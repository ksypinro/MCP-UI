export const PORT = Number(process.env.PORT ?? 4000);

/** PGlite persists here. See README for why this is not a real server yet. */
export const DATABASE_PATH = process.env.DATABASE_PATH ?? './.data';

export const ACCESS_TOKEN_TTL_SECONDS = Number(process.env.ACCESS_TOKEN_TTL_SECONDS ?? 900);
export const REFRESH_TOKEN_TTL_SECONDS = Number(process.env.REFRESH_TOKEN_TTL_SECONDS ?? 2_592_000);

/** Spec section 4.3. Creation beyond this fails with DEVICE_LIMIT_REACHED. */
export const MAX_DEVICES_PER_ACCOUNT = 100;

export const USERNAME_MIN = 3;
export const USERNAME_MAX = 32;
export const PASSWORD_MIN = 12;
export const PASSWORD_MAX = 128;
export const DEVICE_NAME_MAX = 64;
