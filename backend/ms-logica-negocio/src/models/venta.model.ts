import {Entity, model, property} from '@loopback/repository';

@model()
export class Venta extends Entity {
  @property({
    type: 'number',
    required: true,
  })
  numero: number;

  @property({
    type: 'string',
    id: true,
    generated: true,
  })
  id?: string;

  @property({
    type: 'date',
    required: true,
  })
  fecha: string;

  @property({
    type: 'boolean',
    required: true,
  })
  notificada: boolean;


  constructor(data?: Partial<Venta>) {
    super(data);
  }
}

export interface VentaRelations {
  // describe navigational properties here
}

export type VentaWithRelations = Venta & VentaRelations;
