export async function commit(multi: any): Promise<unknown> {
    const res = await multi.exec();
    return res;
}
