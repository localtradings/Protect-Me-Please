import { NextRequest, NextResponse } from 'next/server';

export async function POST(request: NextRequest) {
  const payload = await request.json();
  console.log('received webhook', payload.type);

  return NextResponse.json({ ok: true });
}
