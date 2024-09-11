// user.ts
export interface User {
    id?: number;
    username: string;
    password: string;
    firstName: string;
    lastName: string;
    uid: string;
    interiorEmail: string;
    exteriorEmail: string;
    graduationYear: number;
    isAdmin?: number;
    latestIp?: string;
    deviceUA?: string;
    deviceLang?: string;
    deviceScreenSize?: string;
    createdAt?: Date;
    updatedAt?: Date;
}