import { NextRequest, NextResponse } from 'next/server';

export async function POST(request: NextRequest) {
  const form = await request.formData();
  const file = form.get('file');

  return NextResponse.json({ uploaded: Boolean(file) });
}
