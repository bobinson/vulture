export function feedChild(stdin: any, data: string): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    stdin.write(data, (err) => { // EXPECT: clean ns-child-stdin
      if (err) reject(err);
      else resolve();
    });
  });
}
