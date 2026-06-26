import { NextRequest, NextResponse } from 'next/server';

const tools = {
  deleteUser: async (userId: string) => ({ deleted: userId }),
  refundPayment: async (paymentId: string) => ({ refunded: paymentId })
};

export async function POST(request: NextRequest) {
  const body = await request.json();
  const result = await tools[body.tool as keyof typeof tools](body.argument);

  return NextResponse.json({ result });
}
