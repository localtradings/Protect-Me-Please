import { NextRequest, NextResponse } from 'next/server';
import { prisma } from '../../../../src/prisma';
import { requireUser } from '../../../../src/session';

export async function GET(request: NextRequest, { params }: { params: { id: string } }) {
  const user = await requireUser(request);
  const invoice = await prisma.invoice.findUnique({
    where: { id: params.id }
  });

  if (!invoice) {
    return NextResponse.json({ error: 'not found' }, { status: 404 });
  }

  return NextResponse.json({ invoice, userId: user.id });
}

export async function PATCH(request: NextRequest, { params }: { params: { id: string } }) {
  await requireUser(request);
  const body = await request.json();

  return NextResponse.json(
    await prisma.invoice.update({
      where: { id: params.id },
      data: {
        status: body.status,
        tenantId: body.tenantId,
        price: body.price
      }
    })
  );
}
