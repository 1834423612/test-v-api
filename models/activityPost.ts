export interface ActivityPost {
    id: number;
    title: string;
    date?: string;
    dates: { date: string; duration: number; participants?: number }[];
    location: string;
    categories: string[];
    posterUrl?: string;
    organizer: string;
    organizerEmail: string;
    content: string;
}
