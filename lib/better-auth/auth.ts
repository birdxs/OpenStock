import { betterAuth } from "better-auth";
import { mongodbAdapter } from "better-auth/adapters/mongodb";
import {connectToDatabase} from "@/database/mongoose";
import {nextCookies} from "better-auth/next-js";
import { sendPasswordResetEmail } from "@/lib/nodemailer/reset-password";


let authInstance: ReturnType<typeof betterAuth> | null = null;
let authPromise: Promise<ReturnType<typeof betterAuth>> | null = null;

const getAuth = async () => {
    if (authInstance) {
        return authInstance;
    }
    if (!authPromise) {
        authPromise = (async () => {
            const mongoose = await connectToDatabase();
            const db = mongoose.connection;
            const database = db.db;
            if (!db || !database) {
                throw new Error("MongoDB connection not found!");
            }
            authInstance = betterAuth({
                database: mongodbAdapter(database),
                secret: process.env.BETTER_AUTH_SECRET,
                baseURL: process.env.BETTER_AUTH_URL,
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
                plugins: [nextCookies()],
            });
            return authInstance;
        })();
    }
    return authPromise;
}

// Create a lazy proxy that defers the actual auth initialization until
// the first method call at runtime. This prevents MongoDB connection
// during Next.js build-time SSG prerendering.
function createLazyAuth(): any {
    const cache: Record<string, any> = {};

    return new Proxy(cache, {
        get(target, prop) {
            if (prop in target) {
                return target[prop];
            }

            // For any property access (like 'api'), return a function
            // that awaits the auth instance and forwards the call.
            const forwarded = async (...args: any[]) => {
                const instance = await getAuth();
                const value = (instance as any)[prop];
                if (typeof value === 'function') {
                    return value.apply(instance, args);
                }
                // If it's a nested object (like 'api'), wrap it too
                if (value && typeof value === 'object') {
                    return createNestedProxy(value);
                }
                return value;
            };

            target[prop as string] = forwarded;
            return forwarded;
        },
    });
}

function createNestedProxy(obj: any): any {
    return new Proxy(obj, {
        get(target, prop) {
            const value = (target as any)[prop];
            if (typeof value === 'function') {
                return async (...args: any[]) => {
                    return value.apply(target, args);
                };
            }
            if (value && typeof value === 'object') {
                return createNestedProxy(value);
            }
            return value;
        },
    });
}

export const auth = createLazyAuth();
