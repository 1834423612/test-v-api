export interface ActivityRecord {
    id: number;
    uid: string;
    submission_name: string;
    submission_location: string;
    submission_date: string;
    submission_participate_num?: number;
    submission_description: string;
    hours: number;
    organizer_name: string;
    organizer_email: string;
    status: string;
    is_deleted: number;
    deleted_at?: string;
    created_at: string;
    updated_at: string;
}
