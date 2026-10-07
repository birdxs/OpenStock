import { betterAuth } from "better-auth";
import { mongodbAdapter } from "better-auth/adapters/mongodb";
import { connectToDatabase } from "@/database/mongoose";
import { nextCookies } from "better-auth/next-js";
import { headers } from "next/headers";
import { cache } from "react";
import { sendPasswordResetEmail } from "@/lib/nodemailer/reset-password";

type MongoDb = Parameters<typeof mongodbAdapter>[0];

// Typed from the real config, so additional user fields (country, ...) show up in session types
const createAuth = (database: MongoDb) => betterAuth({
    database: mongodbAdapter(database),
    secret: process.env.BETTER_AUTH_SECRET,
    baseURL: process.env.BETTER_AUTH_URL,
    // Onboarding answers live on the user so the profile page can show and edit them
    user: {
        additionalFields: {
            country: { type: "string", required: false },
            investmentGoals: { type: "string", required: false },
            riskTolerance: { type: "string", required: false },
            preferredIndustry: { type: "string", required: false },
        },
    },
    emailAndPassword: {
        enabled: true,
        disableSignUp: false,
        requireEmailVerification: false,
        minPasswordLength: 8,
        maxPasswordLength: 128,
        autoSignIn: true,
        sendResetPassword: async ({ user, url }) => {
            void sendPasswordResetEmail({
                email: user.email,
                name: user.name,
                resetUrl: url,
            }).catch((error) => {
                console.error('Failed to queue password reset email:', error);
            });
        },
    },
    // Signed session cookie for 5 min: pages stop paying a MongoDB round trip per request.
    // Trade-off: a revoked session can stay valid for up to 5 minutes.
    session: {
        cookieCache: { enabled: true, maxAge: 5 * 60 },
    },
    // No account linking. Sign-up doesn't verify emails, so linking a Google/GitHub identity to an
    // existing account with the same email would let someone pre-register a victim's address and
    // later capture their social sign-in.
    account: {
        accountLinking: { enabled: false },
    },
    // Providers stay disabled until their env vars are set
    socialProviders: {
        google: {
            enabled: !!process.env.GOOGLE_CLIENT_ID,
            clientId: process.env.GOOGLE_CLIENT_ID as string,
            clientSecret: process.env.GOOGLE_CLIENT_SECRET as string,
        },
        github: {
            enabled: !!process.env.GITHUB_CLIENT_ID,
            clientId: process.env.GITHUB_CLIENT_ID as string,
            clientSecret: process.env.GITHUB_CLIENT_SECRET as string,
        },
    },
    plugins: [nextCookies()],
});

type Auth = ReturnType<typeof createAuth>;

let authInstance: Auth | null = null;
let authPromise: Promise<Auth> | null = null;

export const getAuth = async (): Promise<Auth> => {
    if (authInstance) return authInstance;
    if (!authPromise) {
        authPromise = (async () => {
            const mongoose = await connectToDatabase();
            const database = mongoose.connection.db;
            if (!database) {
                throw new Error("MongoDB connection not found!");
            }
            authInstance = createAuth(database);
            return authInstance;
        })();
    }
    return authPromise;
};

/**
 * Lazy proxy for better-auth.
 *
 * - Does NOT touch MongoDB at module-eval time, so Next.js build-time
 *   prerendering (SSG) won't try to connect.
 * - Supports both `auth.handler(req)` (function call) and
 *   `auth.api.getSession(...)` (nested property access) without
 *   pre-resolving the real instance.
 * - Preserves the original better-auth types via `as Auth`.
 */
function createLazyAuth(): Auth {
    const cache = new Map<string, any>();

    const resolvePath = async (path: PropertyKey[]) => {
        const instance = await getAuth();
        let target: any = instance;
        for (let i = 0; i < path.length - 1; i++) {
            target = target[path[i]];
        }
        const value = target[path[path.length - 1]];
        return { target, value };
    };

    const makeProxy = (path: PropertyKey[]): any => {
        const key = path.map(String).join(".");
        const cached = cache.get(key);
        if (cached) return cached;

        const proxy = new Proxy(function () {} as any, {
            get(_target, prop) {
                // Prevent the proxy from being mistaken for a thenable
                // (e.g. `await auth.api` would otherwise hang).
                if (prop === "then") return undefined;
                return makeProxy([...path, prop]);
            },
            apply(_target, _thisArg, args) {
                return (async () => {
                    const { target, value } = await resolvePath(path);
                    if (typeof value === "function") {
                        return value.apply(target, args);
                    }
                    throw new Error(
                        `auth.${path.map(String).join(".")} is not a function`
                    );
                })();
            },
        });

        cache.set(key, proxy);
        return proxy;
    };

    return makeProxy([]) as Auth;
}

export const auth = createLazyAuth();

// One session lookup per request, shared by layouts, pages and actions
export const getSession = cache(async () =>
    auth.api.getSession({ headers: await headers() })
);

// Server actions are public endpoints: never trust a userId sent from the client.
export const requireUserId = async () => {
    const session = await getSession();
    if (!session?.user) throw new Error("Unauthorized");
    return session.user.id;
};
